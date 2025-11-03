# FAQ — XPScerpto

## 1) Mermaid diagrams لا تظهر على GitHub
- استخدم صيغة آمنة: لا تضع أقواس داخل عناوين العقد (`[Active New]` بدل `[Active (New)]`).
- لا تستخدم `|label|` على الحواف؛ استخدم `-- label -->`.
- لا تستخدم `note over` أو `par/and/end`.

## 2) SIGILL عند التشغيل
- هذا يحدث غالباً بسبب اختيار مسار SIMD غير مدعوم. اضبط سياسة الـISA لتقييد التوجيه وقت التشغيل، أو عطّل AVX‑512 مؤقتاً.
- تأكد أن الـbuild flags لم تفرض `-mavx*` عالمياً.

## 3) PCM mismatch في وحدات C++
- احرص على تطابق الأعلام والخيارات (`-pthread`, visibility, sanitizers) بين **كل** أهداف الموديولات والمستهلكين.

## 4) استخدام `xps::expected` مقابل الاستثناءات
- بدون استثناءات: استعمل واجهات `try_*` التي تعيد `xps::expected`.
- مع الاستثناءات: الدوال قد ترمي `api::crypto_error` وبها `.code()`.

## 5) GCM nonce reuse
- لا تعيد استخدام nonce مع نفس المفتاح أبداً. استخدم CSRNG أو عدادات monotonic آمنة.