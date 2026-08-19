plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.mowy.crypto.core.keys"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java.srcDir("../../../bindings/generated")
            jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
        }
    }

    packaging {
        jniLibs.keepDebugSymbols += setOf("**/libmowy_crypto_core.so")
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    testImplementation("junit:junit:4.13.2")
}

val stageRustLibraries by tasks.registering(Sync::class) {
    from("../../../target/aarch64-linux-android/release/libmowy_crypto_core.so") {
        into("arm64-v8a")
    }
    from("../../../target/x86_64-linux-android/release/libmowy_crypto_core.so") {
        into("x86_64")
    }
    into(layout.buildDirectory.dir("generated/jniLibs"))
}

tasks.named("preBuild").configure {
    dependsOn(stageRustLibraries)
}
