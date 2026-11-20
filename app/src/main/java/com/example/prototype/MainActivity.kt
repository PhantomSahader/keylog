package com.example.prototype

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private val TextPrimary = Color(0xFF111827)
private val TextSecondary = Color(0xFF6B7280)
private val AccentBlue = Color(0xFF1E40AF)
private val StatusGreen = Color(0xFF15803D)
private val StatusGreenBg = Color(0xFFDCFCE7)
private val StatusRed = Color(0xFFB91C1C)
private val StatusRedBg = Color(0xFFFEE2E2)
private val SurfaceBg = Color(0xFFF9FAFB)
private val BorderLight = Color(0xFFE5E7EB)

enum class AuthViewMode {
    LOGIN,
    REGISTER,
    RECOVER
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = lightColorScheme(
                    primary = AccentBlue,
                    background = SurfaceBg,
                    surface = Color.White,
                    onBackground = TextPrimary,
                    onSurface = TextPrimary
                )
            ) {
                AccessControlApp()
            }
        }
    }
}

@Composable
fun AccessControlApp() {
    val context = LocalContext.current
    val dbHelper = remember { DatabaseHelper(context.applicationContext) }
    var currentUser by remember { mutableStateOf<String?>(null) }

    if (currentUser == null) {
        AuthScreen(
            dbHelper = dbHelper,
            onAuthSuccess = { loggedUser -> currentUser = loggedUser }
        )
    } else {
        MainControlScreen(
            userName = currentUser!!,
            dbHelper = dbHelper,
            onLogout = { currentUser = null }
        )
    }
}

data class EventLogItem(
    val id: Int,
    val event: String,
    val origin: String,
    val timestamp: String
)

class DatabaseHelper(context: Context) : SQLiteOpenHelper(context, "ControlAccesoIoT_v2.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                recovery_pin_hash TEXT NOT NULL
            )
        """)

        db.execSQL("""
            CREATE TABLE historial_eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evento TEXT NOT NULL,
                origen TEXT NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        val values = ContentValues().apply {
            put("username", "admin")
            put("password_hash", hashValue("Admin@2026"))
            put("recovery_pin_hash", hashValue("inacap2026"))
        }
        db.insert("usuarios", null, values)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS usuarios")
        db.execSQL("DROP TABLE IF EXISTS historial_eventos")
        onCreate(db)
    }

    private fun hashValue(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun registerUser(username: String, password: String, recoveryKeyword: String): Boolean {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("username", username.lowercase())
            put("password_hash", hashValue(password))
            put("recovery_pin_hash", hashValue(recoveryKeyword.lowercase()))
        }
        return db.insert("usuarios", null, values) != -1L
    }

    fun validateLogin(username: String, password: String): Boolean {
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT id FROM usuarios WHERE username = ? AND password_hash = ?",
            arrayOf(username.lowercase(), hashValue(password))
        )
        val exists = cursor.count > 0
        cursor.close()
        return exists
    }

    fun userExists(username: String): Boolean {
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT id FROM usuarios WHERE username = ?",
            arrayOf(username.lowercase())
        )
        val exists = cursor.count > 0
        cursor.close()
        return exists
    }

    fun resetPasswordWithKeyword(username: String, recoveryKeyword: String, newPassword: String): Boolean {
        val db = writableDatabase
        val cursor = db.rawQuery(
            "SELECT id FROM usuarios WHERE username = ? AND recovery_pin_hash = ?",
            arrayOf(username.lowercase(), hashValue(recoveryKeyword.lowercase()))
        )
        val valid = cursor.count > 0
        cursor.close()

        if (!valid) return false

        val values = ContentValues().apply {
            put("password_hash", hashValue(newPassword))
        }
        val updatedRows = db.update(
            "usuarios",
            values,
            "username = ?",
            arrayOf(username.lowercase())
        )
        return updatedRows > 0
    }

    fun logEvent(event: String, origin: String) {
        val db = writableDatabase
        val values = ContentValues().apply {
            put("evento", event)
            put("origen", origin)
        }
        db.insert("historial_eventos", null, values)
    }

    fun getRecentEvents(limit: Int = 5): List<EventLogItem> {
        val list = mutableListOf<EventLogItem>()
        val db = readableDatabase
        val cursor = db.rawQuery(
            "SELECT id, evento, origen, fecha FROM historial_eventos ORDER BY id DESC LIMIT ?",
            arrayOf(limit.toString())
        )
        if (cursor.moveToFirst()) {
            do {
                list.add(
                    EventLogItem(
                        id = cursor.getInt(0),
                        event = cursor.getString(1),
                        origin = cursor.getString(2),
                        timestamp = cursor.getString(3)
                    )
                )
            } while (cursor.moveToNext())
        }
        cursor.close()
        return list
    }
}

data class PasswordCheckResult(
    val hasMinLength: Boolean,
    val hasUppercase: Boolean,
    val hasLowercase: Boolean,
    val hasDigit: Boolean,
    val hasSpecialChar: Boolean
) {
    val isValid: Boolean
        get() = hasMinLength && hasUppercase && hasLowercase && hasDigit && hasSpecialChar
}

fun evaluatePasswordStrength(password: String): PasswordCheckResult {
    return PasswordCheckResult(
        hasMinLength = password.length >= 8,
        hasUppercase = password.any { it.isUpperCase() },
        hasLowercase = password.any { it.isLowerCase() },
        hasDigit = password.any { it.isDigit() },
        hasSpecialChar = password.any { !it.isLetterOrDigit() }
    )
}

@Composable
fun AuthScreen(dbHelper: DatabaseHelper, onAuthSuccess: (String) -> Unit) {
    var mode by remember { mutableStateOf<AuthViewMode>(AuthViewMode.LOGIN) }
    var username by remember { mutableStateOf<String>("") }
    var password by remember { mutableStateOf<String>("") }
    var confirmPassword by remember { mutableStateOf<String>("") }
    var recoveryKeyword by remember { mutableStateOf<String>("") }
    var passwordVisible by remember { mutableStateOf<Boolean>(false) }
    var feedbackMessage by remember { mutableStateOf<String>("") }
    var isError by remember { mutableStateOf<Boolean>(false) }

    val passwordCheck = remember(password) { evaluatePasswordStrength(password) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "KeyGuard",
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = when (mode) {
                    AuthViewMode.LOGIN -> "Control de puertas"
                    AuthViewMode.REGISTER -> "Nuevo usuario"
                    AuthViewMode.RECOVER -> "Restablecer clave"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )

            Spacer(modifier = Modifier.height(28.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, BorderLight)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Text(
                        text = when (mode) {
                            AuthViewMode.LOGIN -> "Iniciar sesión"
                            AuthViewMode.REGISTER -> "Crear cuenta"
                            AuthViewMode.RECOVER -> "Nueva contraseña"
                        },
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )

                    OutlinedTextField(
                        value = username,
                        onValueChange = {
                            username = it
                            feedbackMessage = ""
                        },
                        label = { Text("Usuario") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics { contentDescription = "Usuario" },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )

                    if (mode == AuthViewMode.RECOVER) {
                        OutlinedTextField(
                            value = recoveryKeyword,
                            onValueChange = {
                                recoveryKeyword = it
                                feedbackMessage = ""
                            },
                            label = { Text("Palabra de recuperación") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics { contentDescription = "Palabra de recuperación" },
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    OutlinedTextField(
                        value = password,
                        onValueChange = {
                            password = it
                            feedbackMessage = ""
                        },
                        label = {
                            Text(if (mode == AuthViewMode.RECOVER) "Nueva contraseña" else "Contraseña")
                        },
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            TextButton(onClick = { passwordVisible = !passwordVisible }) {
                                Text(
                                    text = if (passwordVisible) "Ocultar" else "Ver",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = AccentBlue
                                )
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics { contentDescription = "Contraseña" },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )

                    if (mode == AuthViewMode.REGISTER || mode == AuthViewMode.RECOVER) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 4.dp),
                            verticalArrangement = Arrangement.spacedBy(3.dp)
                        ) {
                            RequirementItem("Mínimo 8 caracteres", passwordCheck.hasMinLength)
                            RequirementItem("Mayúscula y minúscula", passwordCheck.hasUppercase && passwordCheck.hasLowercase)
                            RequirementItem("Al menos un número", passwordCheck.hasDigit)
                            RequirementItem("Un carácter especial (@, #, $, %)", passwordCheck.hasSpecialChar)
                        }

                        OutlinedTextField(
                            value = confirmPassword,
                            onValueChange = {
                                confirmPassword = it
                                feedbackMessage = ""
                            },
                            label = { Text("Repite la contraseña") },
                            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics { contentDescription = "Repite la contraseña" },
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    if (mode == AuthViewMode.REGISTER) {
                        OutlinedTextField(
                            value = recoveryKeyword,
                            onValueChange = {
                                recoveryKeyword = it
                                feedbackMessage = ""
                            },
                            label = { Text("Palabra de recuperación") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .semantics { contentDescription = "Palabra de recuperación" },
                            singleLine = true,
                            shape = RoundedCornerShape(12.dp)
                        )
                    }

                    if (feedbackMessage.isNotEmpty()) {
                        Surface(
                            color = if (isError) StatusRedBg else StatusGreenBg,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = feedbackMessage,
                                modifier = Modifier.padding(12.dp),
                                color = if (isError) StatusRed else StatusGreen,
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }

                    Button(
                        onClick = {
                            val cleanUser = username.trim()
                            val cleanPass = password.trim()
                            val cleanKeyword = recoveryKeyword.trim()

                            when (mode) {
                                AuthViewMode.LOGIN -> {
                                    if (cleanUser.isEmpty() || cleanPass.isEmpty()) {
                                        isError = true
                                        feedbackMessage = "Falta usuario o contraseña."
                                    } else if (dbHelper.validateLogin(cleanUser, cleanPass)) {
                                        dbHelper.logEvent("Inicio de sesión", cleanUser)
                                        onAuthSuccess(cleanUser)
                                    } else {
                                        isError = true
                                        feedbackMessage = "Usuario o clave incorrectos."
                                    }
                                }

                                AuthViewMode.REGISTER -> {
                                    if (cleanUser.isEmpty() || cleanPass.isEmpty() || cleanKeyword.isEmpty()) {
                                        isError = true
                                        feedbackMessage = "Completa todos los campos."
                                    } else if (!passwordCheck.isValid) {
                                        isError = true
                                        feedbackMessage = "La clave no cumple los requisitos."
                                    } else if (cleanPass != confirmPassword.trim()) {
                                        isError = true
                                        feedbackMessage = "Las contraseñas no coinciden."
                                    } else if (cleanKeyword.length < 4) {
                                        isError = true
                                        feedbackMessage = "La palabra de recuperación es muy corta."
                                    } else if (dbHelper.userExists(cleanUser)) {
                                        isError = true
                                        feedbackMessage = "Ese usuario ya existe."
                                    } else {
                                        if (dbHelper.registerUser(cleanUser, cleanPass, cleanKeyword)) {
                                            isError = false
                                            feedbackMessage = "Listo, ya puedes entrar."
                                            mode = AuthViewMode.LOGIN
                                            password = ""
                                            confirmPassword = ""
                                            recoveryKeyword = ""
                                        } else {
                                            isError = true
                                            feedbackMessage = "Error al guardar."
                                        }
                                    }
                                }

                                AuthViewMode.RECOVER -> {
                                    if (cleanUser.isEmpty() || cleanKeyword.isEmpty() || cleanPass.isEmpty()) {
                                        isError = true
                                        feedbackMessage = "Completa todos los campos."
                                    } else if (!passwordCheck.isValid) {
                                        isError = true
                                        feedbackMessage = "La nueva clave no cumple los requisitos."
                                    } else if (cleanPass != confirmPassword.trim()) {
                                        isError = true
                                        feedbackMessage = "Las contraseñas no coinciden."
                                    } else {
                                        if (dbHelper.resetPasswordWithKeyword(cleanUser, cleanKeyword, cleanPass)) {
                                            dbHelper.logEvent("Cambio de clave", cleanUser)
                                            isError = false
                                            feedbackMessage = "Clave cambiada."
                                            mode = AuthViewMode.LOGIN
                                            password = ""
                                            confirmPassword = ""
                                            recoveryKeyword = ""
                                        } else {
                                            isError = true
                                            feedbackMessage = "Datos incorrectos."
                                        }
                                    }
                                }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
                    ) {
                        Text(
                            text = when (mode) {
                                AuthViewMode.LOGIN -> "Entrar"
                                AuthViewMode.REGISTER -> "Registrar"
                                AuthViewMode.RECOVER -> "Guardar"
                            },
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            if (mode == AuthViewMode.LOGIN) {
                TextButton(
                    onClick = {
                        mode = AuthViewMode.RECOVER
                        feedbackMessage = ""
                        password = ""
                        confirmPassword = ""
                        recoveryKeyword = ""
                    }
                ) {
                    Text(
                        text = "¿Olvidaste tu contraseña?",
                        color = TextSecondary,
                        fontWeight = FontWeight.Medium
                    )
                }

                TextButton(
                    onClick = {
                        mode = AuthViewMode.REGISTER
                        feedbackMessage = ""
                        password = ""
                        confirmPassword = ""
                        recoveryKeyword = ""
                    }
                ) {
                    Text(
                        text = "Crear cuenta",
                        color = AccentBlue,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            } else {
                TextButton(
                    onClick = {
                        mode = AuthViewMode.LOGIN
                        feedbackMessage = ""
                        password = ""
                        confirmPassword = ""
                        recoveryKeyword = ""
                    }
                ) {
                    Text(
                        text = "Volver",
                        color = AccentBlue,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}

@Composable
private fun RequirementItem(label: String, met: Boolean) {
    Text(
        text = if (met) "✓ $label" else "• $label",
        style = MaterialTheme.typography.bodySmall,
        color = if (met) StatusGreen else TextSecondary,
        fontWeight = if (met) FontWeight.Medium else FontWeight.Normal
    )
}

@Composable
fun MainControlScreen(userName: String, dbHelper: DatabaseHelper, onLogout: () -> Unit) {
    val context = LocalContext.current
    var isWifiActive by remember { mutableStateOf<Boolean>(checkWifiStatus(context)) }
    var localIpAddress by remember { mutableStateOf<String>("Obteniendo...") }
    var targetServerIp by remember { mutableStateOf<String>("192.168.1.100") }
    var isConnected by remember { mutableStateOf<Boolean>(false) }
    var isServerRunning by remember { mutableStateOf<Boolean>(false) }
    var showPairingPanel by remember { mutableStateOf<Boolean>(false) }
    var pairingStatus by remember { mutableStateOf<String>("Desconectado") }

    var lockState by remember { mutableStateOf<String>("Cerrada") }
    var lockDetail by remember { mutableStateOf<String>("Puerta principal") }
    var lastRfidEvent by remember { mutableStateOf<String>("Sin lecturas") }
    var rfidAuthorized by remember { mutableStateOf<Boolean?>(null) }
    var safetyNotice by remember { mutableStateOf<String>("") }
    var recentEvents by remember { mutableStateOf<List<EventLogItem>>(dbHelper.getRecentEvents()) }

    var activeWriter by remember { mutableStateOf<PrintWriter?>(null) }
    var activeServerSocket by remember { mutableStateOf<ServerSocket?>(null) }
    val scope = rememberCoroutineScope()
    var autoCloseJob by remember { mutableStateOf<Job?>(null) }

    LaunchedEffect(isWifiActive) {
        localIpAddress = withContext(Dispatchers.IO) {
            if (isWifiActive) fetchLocalWifiIp() else "No disponible"
        }
    }

    fun recordAndRefresh(event: String, origin: String) {
        dbHelper.logEvent(event, origin)
        recentEvents = dbHelper.getRecentEvents()
    }

    fun closeDoor(reason: String) {
        autoCloseJob?.cancel()
        lockState = "Cerrada"
        lockDetail = reason
        safetyNotice = ""
        recordAndRefresh("Puerta cerrada", reason)
    }

    fun scheduleAutoClose() {
        autoCloseJob?.cancel()
        autoCloseJob = scope.launch {
            delay(5000L)
            lockState = "Cerrada"
            lockDetail = "Cierre automático"
            safetyNotice = "Se cerró automáticamente tras 5s."
            recordAndRefresh("Puerta cerrada", "Automático")
            withContext(Dispatchers.IO) {
                try {
                    activeWriter?.println("C")
                } catch (_: Exception) {
                }
            }
        }
    }

    fun openDoor(reason: String) {
        val currentWifi = checkWifiStatus(context)
        isWifiActive = currentWifi
        if (!currentWifi) {
            autoCloseJob?.cancel()
            lockState = "Cerrada"
            lockDetail = "Sin Wi-Fi"
            safetyNotice = "No se puede abrir: activa el Wi-Fi primero."
            recordAndRefresh("Apertura bloqueada", "Sin conexión Wi-Fi")
            return
        }
        lockState = "Abierta"
        lockDetail = reason
        safetyNotice = "Cierre automático en 5s"
        recordAndRefresh("Puerta abierta", reason)
        scheduleAutoClose()
    }

    DisposableEffect(context) {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networkRequest = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .build()

        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                scope.launch(Dispatchers.Main) {
                    isWifiActive = true
                    if (safetyNotice == "No se puede abrir: activa el Wi-Fi primero.") {
                        safetyNotice = ""
                    }
                }
            }

            override fun onLost(network: Network) {
                scope.launch(Dispatchers.Main) {
                    isWifiActive = false
                    isConnected = false
                    isServerRunning = false
                    activeWriter = null
                    try {
                        activeServerSocket?.close()
                    } catch (_: Exception) {
                    }
                    activeServerSocket = null
                    pairingStatus = "Sin Wi-Fi"
                    localIpAddress = "No disponible"
                    autoCloseJob?.cancel()
                    lockState = "Cerrada"
                    lockDetail = "Sin Wi-Fi"
                    safetyNotice = "Puerta bloqueada por desconexión Wi-Fi."
                    recordAndRefresh("Bloqueo de seguridad", "Wi-Fi apagado")
                }
            }
        }

        connectivityManager.registerNetworkCallback(networkRequest, networkCallback)
        onDispose {
            try {
                connectivityManager.unregisterNetworkCallback(networkCallback)
                activeServerSocket?.close()
            } catch (_: Exception) {
            }
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = userName,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = when {
                            !isWifiActive -> "Wi-Fi desconectado"
                            isConnected || isServerRunning -> "Enlazado por Wi-Fi"
                            else -> "Wi-Fi activo"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (isWifiActive) StatusGreen else StatusRed,
                        fontWeight = FontWeight.Medium
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { showPairingPanel = !showPairingPanel }) {
                        Text(
                            text = if (showPairingPanel) "Cerrar" else "Vincular",
                            color = AccentBlue,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    OutlinedButton(
                        onClick = {
                            autoCloseJob?.cancel()
                            try {
                                activeServerSocket?.close()
                            } catch (_: Exception) {
                            }
                            onLogout()
                        },
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Text("Salir")
                    }
                }
            }

            AnimatedVisibility(visible = showPairingPanel) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, BorderLight)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "Conectar teléfonos",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Tu IP: $localIpAddress ($pairingStatus)",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedTextField(
                                value = targetServerIp,
                                onValueChange = { targetServerIp = it },
                                label = { Text("IP del otro teléfono") },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                shape = RoundedCornerShape(10.dp)
                            )
                            Button(
                                onClick = {
                                    if (!checkWifiStatus(context)) {
                                        isWifiActive = false
                                        pairingStatus = "Sin Wi-Fi"
                                        safetyNotice = "Activa el Wi-Fi para vincular dispositivos."
                                        return@Button
                                    }
                                    scope.launch(Dispatchers.IO) {
                                        try {
                                            withContext(Dispatchers.Main) { pairingStatus = "Conectando..." }
                                            val socket = openTlsClientSocket(targetServerIp.trim(), 8888)
                                            val writer = PrintWriter(socket.getOutputStream(), true)
                                            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                                            withContext(Dispatchers.Main) {
                                                activeWriter = writer
                                                isConnected = true
                                                pairingStatus = "Conectado"
                                                showPairingPanel = false
                                                recordAndRefresh("Vinculado", "Control")
                                            }
                                            while (true) {
                                                val incoming = reader.readLine() ?: break
                                                withContext(Dispatchers.Main) {
                                                    if (incoming.startsWith("RFID:")) {
                                                        val payload = incoming.removePrefix("RFID:")
                                                        lastRfidEvent = payload
                                                        rfidAuthorized = payload.contains("permitido")
                                                        if (rfidAuthorized == true) {
                                                            openDoor("Tarjeta")
                                                        } else {
                                                            recordAndRefresh("Tarjeta rechazada", payload)
                                                        }
                                                    }
                                                }
                                            }
                                        } catch (e: Exception) {
                                            withContext(Dispatchers.Main) {
                                                isConnected = false
                                                pairingStatus = "Sin conexión"
                                                closeDoor("Desconexión")
                                            }
                                        }
                                    }
                                },
                                modifier = Modifier.height(54.dp),
                                shape = RoundedCornerShape(10.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
                            ) {
                                Text("Conectar")
                            }
                        }

                        OutlinedButton(
                            onClick = {
                                if (!checkWifiStatus(context)) {
                                    isWifiActive = false
                                    pairingStatus = "Sin Wi-Fi"
                                    safetyNotice = "Activa el Wi-Fi para activar el modo cerradura."
                                    return@OutlinedButton
                                }
                                if (!isServerRunning) {
                                    isServerRunning = true
                                    scope.launch(Dispatchers.IO) {
                                        try {
                                            val serverSocket = ServerSocket().apply {
                                                reuseAddress = true
                                                bind(InetSocketAddress(8888))
                                            }
                                            activeServerSocket = serverSocket
                                            withContext(Dispatchers.Main) { pairingStatus = "Esperando..." }
                                            val client = serverSocket.accept()
                                            val writer = PrintWriter(client.getOutputStream(), true)
                                            val reader = BufferedReader(InputStreamReader(client.getInputStream()))
                                            withContext(Dispatchers.Main) {
                                                activeWriter = writer
                                                isConnected = true
                                                pairingStatus = "Vinculado"
                                                showPairingPanel = false
                                                recordAndRefresh("Vinculado", "Cerradura")
                                            }
                                            while (true) {
                                                val cmd = reader.readLine() ?: break
                                                withContext(Dispatchers.Main) {
                                                    when (cmd) {
                                                        "O" -> openDoor("Remoto")
                                                        "C" -> closeDoor("Remoto")
                                                    }
                                                }
                                            }
                                        } catch (e: Exception) {
                                            withContext(Dispatchers.Main) {
                                                isServerRunning = false
                                                isConnected = false
                                                pairingStatus = "Desconectado"
                                                closeDoor("Desconexión")
                                            }
                                        }
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(if (isServerRunning) "Recibiendo conexión" else "Activar como cerradura")
                        }
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, BorderLight)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = lockDetail,
                                style = MaterialTheme.typography.labelMedium,
                                color = TextSecondary
                            )
                            Text(
                                text = lockState,
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                                color = if (lockState == "Abierta") StatusGreen else TextPrimary
                            )
                        }

                        Surface(
                            color = if (lockState == "Abierta") StatusGreenBg else StatusRedBg,
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(
                                text = if (lockState == "Abierta") "ABIERTA" else "CERRADA",
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.labelMedium,
                                color = if (lockState == "Abierta") StatusGreen else StatusRed
                            )
                        }
                    }

                    if (safetyNotice.isNotEmpty()) {
                        Surface(
                            color = StatusRedBg,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = safetyNotice,
                                modifier = Modifier.padding(12.dp),
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium,
                                color = StatusRed
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                openDoor("Manual")
                                if (isWifiActive) {
                                    scope.launch(Dispatchers.IO) {
                                        try {
                                            activeWriter?.println("O")
                                        } catch (_: Exception) {
                                        }
                                    }
                                }
                            },
                            enabled = isWifiActive,
                            modifier = Modifier
                                .weight(1f)
                                .height(56.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = StatusGreen)
                        ) {
                            Text("Abrir", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                        }

                        Button(
                            onClick = {
                                closeDoor("Manual")
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        activeWriter?.println("C")
                                    } catch (_: Exception) {
                                    }
                                }
                            },
                            modifier = Modifier
                                .weight(1f)
                                .height(56.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = StatusRed)
                        ) {
                            Text("Cerrar", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, BorderLight)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Tarjeta RFID",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Text(
                        text = lastRfidEvent,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = when (rfidAuthorized) {
                            true -> StatusGreen
                            false -> StatusRed
                            null -> TextSecondary
                        }
                    )
                    OutlinedButton(
                        onClick = {
                            if (!checkWifiStatus(context)) {
                                isWifiActive = false
                                safetyNotice = "No se puede validar tarjeta: Wi-Fi apagado."
                                recordAndRefresh("Lectura bloqueada", "Sin Wi-Fi")
                                return@OutlinedButton
                            }
                            val isAuth = (Math.random() < 0.7)
                            if (isAuth) {
                                val msg = "Tarjeta #A4F2 — Acceso permitido"
                                lastRfidEvent = msg
                                rfidAuthorized = true
                                openDoor("Tarjeta #A4F2")
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        activeWriter?.println("RFID:$msg")
                                    } catch (_: Exception) {
                                    }
                                }
                            } else {
                                val msg = "Tarjeta #99E1 — No autorizada"
                                lastRfidEvent = msg
                                rfidAuthorized = false
                                safetyNotice = "Tarjeta no reconocida."
                                recordAndRefresh("Acceso denegado", "Tarjeta #99E1")
                                scope.launch(Dispatchers.IO) {
                                    try {
                                        activeWriter?.println("RFID:$msg")
                                    } catch (_: Exception) {
                                    }
                                }
                            }
                        },
                        enabled = isWifiActive,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text("Probar tarjeta", fontWeight = FontWeight.Medium)
                    }
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, BorderLight)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "Movimientos recientes",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )

                    if (recentEvents.isEmpty()) {
                        Text(
                            text = "Sin movimientos aún.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    } else {
                        recentEvents.forEach { item ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.event,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = TextPrimary
                                    )
                                    Text(
                                        text = item.origin,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = TextSecondary
                                    )
                                }
                                Text(
                                    text = item.timestamp.takeLast(8),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = TextSecondary
                                )
                            }
                            HorizontalDivider(color = SurfaceBg)
                        }
                    }
                }
            }
        }
    }
}

private fun checkWifiStatus(context: Context): Boolean {
    return try {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    } catch (_: Exception) {
        false
    }
}

private fun openTlsClientSocket(host: String, port: Int): Socket {
    return try {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) {}
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        val factory = sslContext.socketFactory
        try {
            val sslSocket = factory.createSocket(host, port) as SSLSocket
            sslSocket.startHandshake()
            sslSocket
        } catch (tlsEx: Exception) {
            Socket(host, port)
        }
    } catch (e: Exception) {
        Socket(host, port)
    }
}

private fun fetchLocalWifiIp(): String {
    try {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return "No disponible"
        for (intf in interfaces) {
            val addrs = intf.inetAddresses
            for (addr in addrs) {
                if (!addr.isLoopbackAddress && addr is Inet4Address) {
                    return addr.hostAddress ?: "127.0.0.1"
                }
            }
        }
    } catch (_: Exception) {
    }
    return "No disponible"
}