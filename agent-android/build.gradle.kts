plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.green.agent"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.green.agent"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-android"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            assets.srcDir("../server/blocklists")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
