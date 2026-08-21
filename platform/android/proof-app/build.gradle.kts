plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.mowy.crypto.proof"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.mowy.crypto.proof"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        jniLibs.keepDebugSymbols += setOf("**/libjnidispatch.so", "**/libmowy_crypto_core.so")
    }
}

dependencies {
    implementation(project(":key-storage"))
}
