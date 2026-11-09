//go:build windows && (amd64 || arm64)

package winsplit

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DNSWatch reads which program starts a DNS lookup: a real-time ETW session
// with the provider Microsoft-Windows-DNS-Client, event 3006 ("DNS query is
// called"), which Windows writes in the asking process before its DNS
// client service sends the query. See dnsask.go.
type DNSWatch struct {
	tab      askTable
	app      func(pid uint32) string
	logf     func(string)
	session  uint64 // TRACEHANDLE of the session (controller side)
	consumer uint64 // TRACEHANDLE of OpenTrace (consumer side)
	lastHit  atomic.Int64
	flushMu  sync.Mutex
	lastFl   time.Time
	done     chan struct{}
	close    sync.Once
}

var (
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = advapi32.NewProc("StartTraceW")
	procControlTraceW  = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

// Microsoft-Windows-DNS-Client
var dnsClientProvider = windows.GUID{Data1: 0x1C95126E, Data2: 0x7EEA, Data3: 0x49A9, Data4: [8]byte{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}}

const (
	etwSessionName = "TheShuntDNSAskers"

	eventQueryCalled = 3006

	wnodeFlagTracedGUID                = 0x00020000
	eventTraceRealTimeMode             = 0x00000100
	eventTraceControlStop              = 1
	eventTraceControlFlush             = 3
	eventControlCodeEnable             = 1
	traceLevelVerbose                  = 5 // 3006 is information (4); verbose in case a build files it lower
	processTraceModeRealTime           = 0x00000100
	processTraceModeEventRecord        = 0x10000000
	invalidProcessTraceHandle          = ^uint64(0)
	clientContextSystemTime            = 2
	filetimeUnixOffset100ns            = 116444736000000000
	flushEvery                         = 5 * time.Millisecond
	errorAlreadyExists                 = 183
	allKeywords                 uint64 = ^uint64(0)
)

// The structures below follow evntrace.h / evntcons.h (64-bit layout).

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// traceProps is EVENT_TRACE_PROPERTIES with room for the session name, which
// ETW copies behind it.
type traceProps struct {
	p    eventTraceProperties
	name [128]uint16
}

func newTraceProps() *traceProps {
	tp := &traceProps{}
	tp.p.Wnode.BufferSize = uint32(unsafe.Sizeof(*tp))
	tp.p.Wnode.Flags = wnodeFlagTracedGUID
	tp.p.Wnode.ClientContext = clientContextSystemTime
	tp.p.LoggerNameOffset = uint32(unsafe.Offsetof(tp.name))
	return tp
}

type eventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    windows.GUID
	ID            uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64
	ProcessorTime uint64
	ActivityID    windows.GUID
}

type eventRecord struct {
	Header            eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer
	UserData          *byte
	UserContext       unsafe.Pointer
}

// eventTraceLogfile is EVENT_TRACE_LOGFILEW; the parts this watch does not
// read are kept as bytes of the right size.
type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte  // EVENT_TRACE
	LogfileHeader       [280]byte // TRACE_LOGFILE_HEADER
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// one callback for the process (callbacks are never freed); it hands the
// events to the watch that runs
var (
	activeWatch atomic.Pointer[DNSWatch]
	cbOnce      sync.Once
	cbPtr       uintptr
)

func eventCallback() uintptr {
	cbOnce.Do(func() {
		cbPtr = windows.NewCallback(func(r *eventRecord) uintptr {
			if w := activeWatch.Load(); w != nil && r != nil {
				w.onEvent(r)
			}
			return 0
		})
	})
	return cbPtr
}

// StartDNSWatch starts the ETW session. app maps a process ID to its app ID
// (Owners.App); logf (may be nil) gets one line when the first lookup is
// seen. Only one watch runs at a time; Close ends it.
func StartDNSWatch(app func(pid uint32) string, logf func(string)) (*DNSWatch, error) {
	if unsafe.Sizeof(eventTraceLogfile{}) != 448 || unsafe.Sizeof(eventRecord{}) != 112 || unsafe.Sizeof(eventTraceProperties{}) != 120 {
		return nil, errors.New("ETW structures do not match this platform")
	}
	if err := procStartTraceW.Find(); err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(etwSessionName)
	w := &DNSWatch{app: app, logf: logf, done: make(chan struct{})}
	start := func() uintptr {
		tp := newTraceProps()
		tp.p.LogFileMode = eventTraceRealTimeMode
		tp.p.BufferSize = 16 // KB
		tp.p.MinimumBuffers = 4
		tp.p.MaximumBuffers = 32
		tp.p.FlushTimer = 1 // s; queries flush at once (flush)
		r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&w.session)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(tp)))
		return r
	}
	r := start()
	if r == errorAlreadyExists { // left over from a crash: end it and start anew
		stopSession(0, name)
		r = start()
	}
	if r != 0 {
		return nil, fmt.Errorf("StartTrace: %w", windows.Errno(r))
	}
	if r, _, _ := procEnableTraceEx2.Call(uintptr(w.session), uintptr(unsafe.Pointer(&dnsClientProvider)), eventControlCodeEnable,
		traceLevelVerbose, uintptr(allKeywords), 0, 0, 0); r != 0 {
		stopSession(w.session, nil)
		return nil, fmt.Errorf("EnableTraceEx2: %w", windows.Errno(r))
	}
	lf := &eventTraceLogfile{LoggerName: name, ProcessTraceMode: processTraceModeRealTime | processTraceModeEventRecord,
		EventRecordCallback: eventCallback()}
	h, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	if uint64(h) == invalidProcessTraceHandle {
		stopSession(w.session, nil)
		return nil, fmt.Errorf("OpenTrace: %w", err)
	}
	w.consumer = uint64(h)
	if !activeWatch.CompareAndSwap(nil, w) {
		procCloseTrace.Call(uintptr(w.consumer))
		stopSession(w.session, nil)
		return nil, errors.New("a DNS watch runs already")
	}
	go func() {
		defer close(w.done)
		handles := [1]uint64{w.consumer}
		procProcessTrace.Call(uintptr(unsafe.Pointer(&handles[0])), 1, 0, 0) // returns when the session ends
	}()
	return w, nil
}

func stopSession(h uint64, name *uint16) {
	tp := newTraceProps()
	procControlTraceW.Call(uintptr(h), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(tp)), eventTraceControlStop)
}

// Close ends the session.
func (w *DNSWatch) Close() {
	w.close.Do(func() {
		activeWatch.CompareAndSwap(w, nil)
		stopSession(w.session, nil)
		procCloseTrace.Call(uintptr(w.consumer))
		select {
		case <-w.done:
		case <-time.After(3 * time.Second):
		}
	})
}

func (w *DNSWatch) onEvent(r *eventRecord) {
	if r.Header.ID != eventQueryCalled || r.Header.ProviderID != dnsClientProvider || r.UserData == nil || r.UserDataLength < 4 {
		return
	}
	name := queryName(unsafe.Slice(r.UserData, int(r.UserDataLength)))
	if name == "" {
		return
	}
	app := w.app(r.Header.ProcessID)
	if app == "" {
		return
	}
	at := time.Unix(0, (r.Header.TimeStamp-filetimeUnixOffset100ns)*100)
	if d := time.Since(at); d < -time.Minute || d > time.Minute {
		at = time.Now() // a clock step: the arrival is close enough
	}
	w.tab.add(name, app, at)
	if w.lastHit.Swap(time.Now().UnixNano()) == 0 && w.logf != nil {
		w.logf("DNS askers: lookup events arrive")
	}
}

// flush hands the events in ETW's buffers to the callback now (it would wait
// up to a second otherwise); at most every flushEvery.
func (w *DNSWatch) flush() {
	w.flushMu.Lock()
	if time.Since(w.lastFl) < flushEvery {
		w.flushMu.Unlock()
		return
	}
	w.lastFl = time.Now()
	w.flushMu.Unlock()
	tp := newTraceProps()
	procControlTraceW.Call(uintptr(w.session), 0, uintptr(unsafe.Pointer(tp)), eventTraceControlFlush)
}

// Askers returns the programs that asked for name (newest first), waiting
// briefly for the event of the ask that made the query that arrived now.
func (w *DNSWatch) Askers(name string, arrived time.Time) []string {
	if name = normName(name); name == "" {
		return nil
	}
	w.flush()
	deadline := arrived.Add(askWait)
	for {
		apps, fresh, changed := w.tab.get(name, time.Now(), arrived.Add(-askFresh))
		left := time.Until(deadline)
		if fresh || left <= 0 {
			return apps
		}
		t := time.NewTimer(min(left, 40*time.Millisecond))
		select {
		case <-changed:
		case <-t.C:
			w.flush() // events may sit in a buffer that filled meanwhile
		}
		t.Stop()
	}
}
