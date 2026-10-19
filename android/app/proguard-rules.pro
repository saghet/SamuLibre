# SamuLibre Proguard Rules
-keep class org.samulibre.app.NativeBridge { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
-keepclassmembers class org.samulibre.app.MainActivity$WebAppInterface {
    <methods>;
}
