package com.example.phone2pc.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.example.phone2pc.R
import com.example.phone2pc.biometric.BiometricHandler
import com.example.phone2pc.ble.FidoAdvertiser
import com.example.phone2pc.ble.FidoGattServer
import com.example.phone2pc.crypto.KeystoreManager
import com.example.phone2pc.ctap.CtapRouter
import com.example.phone2pc.model.CredentialStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * MainActivity
 *
 * The single entry-point Activity. Handles:
 *   1. Requesting runtime permissions (Bluetooth, Biometrics).
 *   2. Providing the visual status of the FIDO authenticator service.
 *   3. Anchoring the [BiometricHandler] prompt.
 *   4. Wiring all components together (Dependency Injection).
 *
 * Phase: 3 — Integration and UI
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    private lateinit var tvAdvertisingStatus: TextView
    private lateinit var tvConnectionStatus: TextView

    private lateinit var fidoGattServer: FidoGattServer
    private lateinit var fidoAdvertiser: FidoAdvertiser
    private lateinit var ctapRouter: CtapRouter
    
    private val biometricHandler = BiometricHandler()
    private val keystoreManager = KeystoreManager()
    private lateinit var credentialStore: CredentialStore

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.entries.all { it.value }
        if (allGranted) {
            startBleServices()
        } else {
            tvAdvertisingStatus.text = "Advertising: Failed (Permissions Denied)"
            Log.e(TAG, "Permissions denied")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        
        tvAdvertisingStatus = findViewById(R.id.tvAdvertisingStatus)
        tvConnectionStatus = findViewById(R.id.tvConnectionStatus)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        // Initialize dependencies
        credentialStore = CredentialStore(this)
        
        // Wire CtapRouter with BiometricHandler and CredentialStore
        ctapRouter = CtapRouter(keystoreManager, credentialStore) { signature ->
            // This lambda is called by CtapRouter when it needs biometric auth
            
            // FIDO Spec: Send KEEPALIVE (0x82) with UP_NEEDED (0x02) status periodically 
            // while waiting for user interaction so the OS doesn't time out and retry.
            val keepAliveJob = lifecycleScope.launch {
                while (isActive) {
                    delay(400) // Send keepalive every 400ms
                    fidoGattServer.sendResponse(0x82.toByte(), byteArrayOf(0x02))
                }
            }

            // We suspend here and delegate to the BiometricHandler, anchoring to this Activity.
            val result = biometricHandler.authenticate(this@MainActivity, signature)
            
            keepAliveJob.cancel()
            
            if (result is BiometricHandler.AuthResult.Success) {
                result.signature
            } else {
                null
            }
        }

        fidoGattServer = FidoGattServer(this)
        fidoAdvertiser = FidoAdvertiser(this)

        // Wire BLE to CtapRouter
        fidoGattServer.onMessageReceived = { message ->
            lifecycleScope.launch {
                try {
                    val response = ctapRouter.process(message)
                    fidoGattServer.sendResponse(0x83.toByte(), response)
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing CTAP message", e)
                }
            }
        }

        // Wire UI status updates
        fidoGattServer.onConnectionStateChanged = { connected ->
            runOnUiThread {
                if (connected) {
                    tvConnectionStatus.text = "Connection: Connected to PC"
                } else {
                    tvConnectionStatus.text = "Connection: Disconnected"
                }
            }
        }

        fidoAdvertiser.onStateChanged = { advertising, error ->
            runOnUiThread {
                if (advertising) {
                    tvAdvertisingStatus.text = "Advertising: Yes (Discoverable)"
                } else {
                    tvAdvertisingStatus.text = "Advertising: Stopped" + if (error != null) " ($error)" else ""
                }
            }
        }

        checkAndRequestPermissions()
    }

    private fun checkAndRequestPermissions() {
        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE
            )
        } else {
            arrayOf(
                Manifest.permission.BLUETOOTH,
                Manifest.permission.BLUETOOTH_ADMIN,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        }

        val missingPermissions = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isEmpty()) {
            startBleServices()
        } else {
            requestPermissionLauncher.launch(missingPermissions.toTypedArray())
        }
    }

    private val requestEnableBluetoothLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            actuallyStartBleServices()
        } else {
            tvAdvertisingStatus.text = "Advertising: Failed (Bluetooth is off)"
            Log.e(TAG, "User declined to enable Bluetooth")
        }
    }

    private fun startBleServices() {
        val bluetoothManager = getSystemService(android.content.Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
        val bluetoothAdapter = bluetoothManager?.adapter
        
        if (bluetoothAdapter == null) {
            tvAdvertisingStatus.text = "Advertising: Failed (Device doesn't support Bluetooth)"
            return
        }

        if (!bluetoothAdapter.isEnabled) {
            // Bluetooth is off, prompt the user to turn it on
            val enableBtIntent = android.content.Intent(android.bluetooth.BluetoothAdapter.ACTION_REQUEST_ENABLE)
            requestEnableBluetoothLauncher.launch(enableBtIntent)
        } else {
            // Bluetooth is already on
            actuallyStartBleServices()
        }
    }

    private fun actuallyStartBleServices() {
        fidoGattServer.start()
        fidoAdvertiser.startAdvertising()
    }

    override fun onDestroy() {
        super.onDestroy()
        fidoAdvertiser.stopAdvertising()
        fidoGattServer.stop()
    }
}

