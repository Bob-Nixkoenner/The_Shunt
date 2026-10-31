plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Version from the git tag (v0.7.0-rc4 -> "0.7.0-rc4", 2 commits later
// "0.7.0-rc4-2-gabc1234", uncommitted changes "…-dirty"); versionCode = (major*10000 + minor*100 + patch)*100 + rc,
// rc = N of "-rcN", 99 for a release without rc (Google Play wants a higher versionCode with every upload).
// -PshuntVersion=v0.7.0 builds as that version (to test the in-app update)
val gitVersion: String = providers.gradleProperty("shuntVersion").orNull?.removePrefix("v") ?: runCatching {
    providers.exec { commandLine("git", "describe", "--tags", "--dirty", "--match", "v[0-9]*") }
        .standardOutput.asText.get().trim().removePrefix("v")
}.getOrDefault("").ifEmpty { "0.0.0-dev" }
val gitVersionCode: Int = Regex("""^(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?""").find(gitVersion)
    ?.destructured?.let { (a, b, c, rc) -> (a.toInt() * 10000 + b.toInt() * 100 + c.toInt()) * 100 + (rc.toIntOrNull()?.coerceAtMost(98) ?: 99) }
    ?.takeIf { it > 0 } ?: 1 // no tag (shallow clone): 0.0.0-dev, but Android needs >= 1

android {
    namespace = "org.theshunt.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.theshunt.app"
        minSdk = 29 // getConnectionOwnerUid: which app owns a connection
        targetSdk = 36
        versionCode = gitVersionCode
        versionName = gitVersion
    }

    // the texts of the desktop apps are the texts of this app (one catalog,
    // internal/i18n/lang/<code>.json): packed as assets, read by I18n
    sourceSets.getByName("main").assets.srcDir("../../internal/i18n/lang")

    // Fixed release key (CI secret): without it every build gets a random debug key
    // and Android refuses to update an installed app. Local builds keep the debug key.
    val releaseKeystore = System.getenv("SHUNT_KEYSTORE")?.takeIf { file(it).exists() }
    if (releaseKeystore != null) {
        signingConfigs.create("shunt") {
            storeFile = file(releaseKeystore)
            storeType = "pkcs12"
            storePassword = System.getenv("SHUNT_KEYSTORE_PASSWORD")
            keyAlias = "shunt"
            keyPassword = System.getenv("SHUNT_KEYSTORE_PASSWORD")
        }
        buildTypes.getByName("debug").signingConfig = signingConfigs.getByName("shunt")
    }

    // github: the APK from the GitHub release, updates itself. play: the bundle for Google Play,
    // which updates apps itself (no install permission, the update section only points to Play).
    flavorDimensions += "dist"
    productFlavors {
        create("github") { dimension = "dist" }
        create("play") { dimension = "dist" }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // the bundle for Play is signed with the same key (as upload key)
            if (releaseKeystore != null) signingConfig = signingConfigs.getByName("shunt")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    // libopenvpn.so is a program, not a library: it must exist as a file in
    // nativeLibraryDir to be started, so native libs are extracted on install
    packaging {
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    // Go core (../../mobile), built by ../build-core.sh with gomobile
    implementation(files("libs/shunt-core.aar"))

    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.core:core-ktx:1.15.0")
    // QR import of WireGuard configs
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    testImplementation("junit:junit:4.13.2")
}
