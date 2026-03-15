package com.juanma0511.rootdetector

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.*
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.juanma0511.rootdetector.ui.*

data class NavItem(
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

val navItems = listOf(
    NavItem("Root Check",   Icons.Filled.Security,  Icons.Outlined.Security),
    NavItem("HW Security",  Icons.Filled.Hardware,  Icons.Outlined.Hardware),
    NavItem("Settings",     Icons.Filled.Settings,  Icons.Outlined.Settings)
)

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val prefs = getSharedPreferences("rootdetector_prefs", Context.MODE_PRIVATE)
            var themeMode by remember {
                mutableStateOf(
                    when (prefs.getString("theme_mode", "SYSTEM")) {
                        "LIGHT" -> ThemeMode.LIGHT
                        "DARK"  -> ThemeMode.DARK
                        else    -> ThemeMode.SYSTEM
                    }
                )
            }

            RootDetectorTheme(themeMode = themeMode) {
                MainShell(
                    viewModel   = viewModel,
                    themeMode   = themeMode,
                    onThemeChange = { mode ->
                        themeMode = mode
                        prefs.edit().putString("theme_mode", mode.name).apply()
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainShell(
    viewModel: MainViewModel,
    themeMode: ThemeMode,
    onThemeChange: (ThemeMode) -> Unit
) {
    var selectedTab by remember { mutableIntStateOf(0) }

    val titles = listOf("Root Detector", "Hardware Security", "Settings")

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        titles[selectedTab],
                        style = MaterialTheme.typography.titleLarge
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar {
                navItems.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected  = selectedTab == index,
                        onClick   = { selectedTab = index },
                        icon = {
                            Icon(
                                imageVector = if (selectedTab == index) item.selectedIcon
                                              else item.unselectedIcon,
                                contentDescription = item.label
                            )
                        },
                        label = { Text(item.label) }
                    )
                }
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            AnimatedContent(
                targetState = selectedTab,
                transitionSpec = {
                    if (targetState > initialState) {
                        slideInHorizontally { it } + fadeIn() togetherWith
                            slideOutHorizontally { -it } + fadeOut()
                    } else {
                        slideInHorizontally { -it } + fadeIn() togetherWith
                            slideOutHorizontally { it } + fadeOut()
                    }
                },
                label = "tab_transition"
            ) { tab ->
                when (tab) {
                    0    -> RootDetectorScreen(viewModel)
                    1    -> HwSecurityScreen(viewModel)
                    else -> SettingsScreen(
                                currentTheme = themeMode,
                                onThemeChange = onThemeChange
                            )
                }
            }
        }
    }
}
