package org.theshunt.app

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Typeface
import android.graphics.drawable.Icon

/**
 * The status bar icon with the number of active tunnels: the track switch
 * of ic_notify, smaller, and the digit at the lower right. The status bar
 * only uses the shape (alpha), so everything is drawn in white.
 */
object StatusIcon {
    private val cache = HashMap<Int, Icon>()

    /** n = 0: the plain icon; more than 9 shows 9. */
    @Synchronized
    fun create(n: Int): Icon = cache.getOrPut(n.coerceIn(0, 9)) { draw(n.coerceIn(0, 9)) }

    private fun draw(n: Int): Icon {
        val size = 96
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp)
        val p = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            style = Paint.Style.STROKE
            strokeCap = Paint.Cap.ROUND
            strokeJoin = Paint.Join.ROUND
        }
        // same path as drawable/ic_notify.xml (viewport 32)
        val glyph = Path().apply {
            moveTo(3f, 24f); rLineTo(8f, 0f); rLineTo(10f, -16f); rLineTo(8f, 0f)
            moveTo(11f, 24f); rLineTo(18f, 0f)
        }
        c.save()
        val k = size / 32f
        if (n > 0) c.scale(k * 0.72f, k * 0.72f, 0f, 0f) else c.scale(k, k)
        p.strokeWidth = if (n > 0) 4.2f else 3f
        c.drawPath(glyph, p)
        c.restore()
        if (n > 0) {
            val t = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = Color.WHITE
                typeface = Typeface.DEFAULT_BOLD
                textSize = 58f
                textAlign = Paint.Align.CENTER
            }
            c.drawText(n.toString(), size * 0.74f, size * 0.96f, t)
        }
        return Icon.createWithBitmap(bmp)
    }
}
