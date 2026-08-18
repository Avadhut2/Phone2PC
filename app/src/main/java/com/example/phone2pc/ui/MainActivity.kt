package com.example.phone2pc.ui

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.phone2pc.R

/**
 * MainActivity
 *
 * The single entry-point Activity. Intentionally thin — it only handles:
 *   1. Requesting runtime permissions (Bluetooth, Biometrics).
 *   2. Providing the visual status of the FIDO authenticator service.
 *   3. Anchoring the [com.example.phone2pc.biometric.BiometricHandler] prompt.
 *
 * All business logic lives in the ble/, ctap/, crypto/, and biometric/ packages.
 *
 * Phase: 0 → progressively wired as phases complete.
 */
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        // TODO(Phase 1): Request BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT permissions.
        // TODO(Phase 1): Start FidoGattServer and FidoAdvertiser.
    }
}
