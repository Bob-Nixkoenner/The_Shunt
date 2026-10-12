package main

/*
#cgo pkg-config: gtk+-3.0 webkit2gtk-4.1
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

static GtkWidget *win;
static WebKitWebView *view;
static char *allowed_prefix; // only our local UI may load in the window

extern void goWindowHidden(void);
extern void goOpenExternal(char *uri);

// Closing the window hides it; the app keeps running in the tray.
static gboolean on_delete(GtkWidget *w, GdkEvent *e, gpointer d) {
	gtk_widget_hide(w);
	goWindowHidden();
	return TRUE;
}

// Navigation outside the local UI never happens inside the window: links
// open in the user's browser, everything else is refused.
static gboolean on_decide(WebKitWebView *v, WebKitPolicyDecision *dec, WebKitPolicyDecisionType type, gpointer d) {
	if (type != WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION && type != WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION)
		return FALSE;
	WebKitNavigationAction *a = webkit_navigation_policy_decision_get_navigation_action(WEBKIT_NAVIGATION_POLICY_DECISION(dec));
	const char *uri = webkit_uri_request_get_uri(webkit_navigation_action_get_request(a));
	if (allowed_prefix && uri && strncmp(uri, allowed_prefix, strlen(allowed_prefix)) == 0 && type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION)
		return FALSE;
	if (uri && (g_str_has_prefix(uri, "https://") || g_str_has_prefix(uri, "http://")))
		goOpenExternal((char *)uri);
	webkit_policy_decision_ignore(dec);
	return TRUE;
}

// Shown instead of a blank window when the page cannot load.
static gboolean on_load_failed(WebKitWebView *v, WebKitLoadEvent ev, gchar *uri, GError *err, gpointer d) {
	gchar *html = g_markup_printf_escaped("<body style='font-family:sans-serif;padding:2em'><h2>The Shunt</h2><p>Cannot load the interface: %s</p></body>", err ? err->message : "unknown error");
	webkit_web_view_load_alternate_html(v, html, uri, NULL);
	g_free(html);
	return TRUE;
}

static void shunt_init(const char *title, const char *prefix, const char *icon_png, int icon_len) {
	// VMs and some GPU drivers render WebKit's DMA-BUF/GL output as a white
	// window. This UI needs no GPU, so stay on the safe software path.
	g_setenv("WEBKIT_DISABLE_DMABUF_RENDERER", "1", FALSE);
	g_setenv("WEBKIT_DISABLE_COMPOSITING_MODE", "1", FALSE);
	g_set_prgname("the-shunt"); // WM_CLASS, matches StartupWMClass in the .desktop file
	gtk_init(NULL, NULL);
	allowed_prefix = g_strdup(prefix);
	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), title);
	gtk_window_set_default_size(GTK_WINDOW(win), 1240, 860);
	if (icon_len > 0) {
		GInputStream *s = g_memory_input_stream_new_from_data(g_memdup2(icon_png, icon_len), icon_len, g_free);
		GdkPixbuf *pb = gdk_pixbuf_new_from_stream(s, NULL, NULL);
		if (pb) { gtk_window_set_icon(GTK_WINDOW(win), pb); g_object_unref(pb); }
		g_object_unref(s);
	}
	WebKitWebContext *ctx = webkit_web_context_new_ephemeral(); // no cache/cookies on disk
	view = WEBKIT_WEB_VIEW(webkit_web_view_new_with_context(ctx));
	WebKitSettings *st = webkit_web_view_get_settings(view);
	webkit_settings_set_enable_developer_extras(st, FALSE);
	webkit_settings_set_javascript_can_open_windows_automatically(st, FALSE);
	webkit_settings_set_hardware_acceleration_policy(st, WEBKIT_HARDWARE_ACCELERATION_POLICY_NEVER);
	gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(view));
	g_signal_connect(win, "delete-event", G_CALLBACK(on_delete), NULL);
	g_signal_connect(view, "decide-policy", G_CALLBACK(on_decide), NULL);
	g_signal_connect(view, "load-failed", G_CALLBACK(on_load_failed), NULL);
}

static gboolean do_show(gpointer uri) {
	if (uri) { webkit_web_view_load_uri(view, (char *)uri); g_free(uri); }
	gtk_widget_show_all(win);
	gtk_window_present(GTK_WINDOW(win));
	return G_SOURCE_REMOVE;
}
static void shunt_show(const char *uri) { g_idle_add(do_show, uri ? g_strdup(uri) : NULL); }

static gboolean do_quit(gpointer d) { gtk_main_quit(); return G_SOURCE_REMOVE; }
static void shunt_quit(void) { g_idle_add(do_quit, NULL); }
static void shunt_main(void) { gtk_main(); }
*/
import "C"

import (
	"os/exec"
	"unsafe"
)

var onHidden = func() {}

//export goWindowHidden
func goWindowHidden() { onHidden() }

//export goOpenExternal
func goOpenExternal(uri *C.char) {
	_ = exec.Command("xdg-open", C.GoString(uri)).Start()
}

// windowInit must run on the main OS thread before windowMain.
func windowInit(title, allowedPrefix string, icon []byte) {
	ct, cp := C.CString(title), C.CString(allowedPrefix)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cp))
	var ip *C.char
	if len(icon) > 0 {
		ip = (*C.char)(C.CBytes(icon))
		defer C.free(unsafe.Pointer(ip))
	}
	C.shunt_init(ct, cp, ip, C.int(len(icon)))
}

// windowShow shows the window (thread safe); uri "" keeps the current page.
func windowShow(uri string) {
	if uri == "" {
		C.shunt_show(nil)
		return
	}
	cu := C.CString(uri)
	defer C.free(unsafe.Pointer(cu))
	C.shunt_show(cu)
}

func windowQuit() { C.shunt_quit() }

// windowMain runs the GTK loop on the calling (main) thread.
func windowMain() { C.shunt_main() }
