// SPDX-License-Identifier: GPL-3.0-or-later
package dev.flicker.vpn

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.view.animation.OvershootInterpolator
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsControllerCompat

/**
 * v4.12.1: заставка со змейками (из 4.11.3-debug).
 * 1850 мс + fade 280 мс → MainActivity. Без логики VPN.
 */
class SplashActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = false
            isAppearanceLightNavigationBars = false
        }
        setContentView(R.layout.activity_splash)
        val splashRoot = findViewById<View>(R.id.splashRoot)
        val glow = findViewById<View>(R.id.glow)
        val snakeArt = findViewById<View>(R.id.snakeArt)
        val tongue = findViewById<View>(R.id.tongue)
        val titleFlicker = findViewById<View>(R.id.titleFlicker)
        val titleVpn = findViewById<View>(R.id.titleVpn)
        val tagline = findViewById<View>(R.id.tagline)
        val shimmer = findViewById<View>(R.id.shimmer)

        snakeArt.scaleX = 0.82f
        snakeArt.scaleY = 0.82f
        snakeArt.alpha = 0f
        glow.alpha = 0f
        glow.scaleX = 0.6f
        glow.scaleY = 0.6f

        val ease = AccelerateDecelerateInterpolator()
        val overshoot = OvershootInterpolator(1.15f)

        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(snakeArt, View.ALPHA, 0f, 1f).setDuration(520),
                ObjectAnimator.ofFloat(snakeArt, View.SCALE_X, 0.82f, 1f).setDuration(700),
                ObjectAnimator.ofFloat(snakeArt, View.SCALE_Y, 0.82f, 1f).setDuration(700),
                ObjectAnimator.ofFloat(glow, View.ALPHA, 0f, 0.85f).setDuration(700),
                ObjectAnimator.ofFloat(glow, View.SCALE_X, 0.6f, 1.15f).setDuration(900),
                ObjectAnimator.ofFloat(glow, View.SCALE_Y, 0.6f, 1.15f).setDuration(900)
            )
            interpolator = ease
            start()
        }
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(tongue, View.ALPHA, 0f, 1f).setDuration(180),
                ObjectAnimator.ofFloat(tongue, View.TRANSLATION_Y, -12f, 18f).setDuration(420),
                ObjectAnimator.ofFloat(tongue, View.SCALE_Y, 0.4f, 1f).setDuration(420)
            )
            interpolator = overshoot
            startDelay = 380
            start()
        }
        ObjectAnimator.ofFloat(tongue, View.ROTATION, 0f, -8f, 6f, -4f, 0f).apply {
            duration = 700
            startDelay = 780
            interpolator = ease
            start()
        }
        ObjectAnimator.ofFloat(snakeArt, View.SCALE_X, 1f, 1.03f, 1f).apply {
            duration = 1400
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.RESTART
            interpolator = ease
            startDelay = 700
            start()
        }
        ObjectAnimator.ofFloat(snakeArt, View.SCALE_Y, 1f, 1.03f, 1f).apply {
            duration = 1400
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.RESTART
            interpolator = ease
            startDelay = 700
            start()
        }
        ObjectAnimator.ofFloat(
            shimmer, View.TRANSLATION_X, -120f,
            40f + resources.displayMetrics.widthPixels.toFloat()
        ).apply {
            duration = 1100
            interpolator = LinearInterpolator()
            startDelay = 200
            repeatCount = 1
            start()
        }
        AnimatorSet().apply {
            playTogether(
                ObjectAnimator.ofFloat(titleFlicker, View.ALPHA, 0f, 1f).setDuration(420),
                ObjectAnimator.ofFloat(titleFlicker, View.TRANSLATION_Y, 24f, 0f).setDuration(480),
                ObjectAnimator.ofFloat(titleVpn, View.ALPHA, 0f, 1f).setDuration(420),
                ObjectAnimator.ofFloat(titleVpn, View.TRANSLATION_Y, 18f, 0f).setDuration(480),
                ObjectAnimator.ofFloat(tagline, View.ALPHA, 0f, 1f).setDuration(500)
            )
            interpolator = DecelerateInterpolator()
            startDelay = 520
            start()
        }
        ObjectAnimator.ofFloat(glow, View.ALPHA, 0.55f, 0.95f, 0.55f).apply {
            duration = 1600
            repeatCount = ValueAnimator.INFINITE
            interpolator = ease
            startDelay = 600
            start()
        }

        splashRoot.postDelayed({
            splashRoot.animate().alpha(0f).setDuration(280).withEndAction {
                startActivity(Intent(this, MainActivity::class.java))
                overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out)
                finish()
            }.start()
        }, 1850)
    }
}
