plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.pqtunnel.app"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.pqtunnel.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies { implementation(files("libs/pqtunnel-mobile.aar")) }
