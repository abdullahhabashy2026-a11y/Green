# Green Project Context / سياق مشروع Green

This document records the current project state so development can continue later with any developer or AI model.

هذا الملف يوثق الحالة الحالية للمشروع حتى يمكن استكماله لاحقا بواسطة أي مطور أو نموذج ذكاء اصطناعي.

---

## العربية

### المرحلة الحالية

```text
windows-dns-local-proof-of-concept
```

هذه المرحلة تثبت مسار Windows المحلي: داشبورد للأدمن، تفعيل Agent بالتوكن، heartbeat كل 60 ثانية، حجب DNS، قوائم حجب Adult يتم تحديثها/استيرادها، حماية استرجاع DNS، وتحسين مبدئي لتقليل الحجب الخاطئ عبر Allowlist داخل الـ Agent.

### الهدف العام

مشروع `Green` هو نظام مبدئي لمتابعة وحماية أجهزة Windows. الهدف النهائي هو منع تصفح المواقع الإباحية ومواقع التواصل الاجتماعي على أجهزة الكمبيوتر والموبايل. النسخة الحالية تثبت وجود الـ Agent على الجهاز، ترسل حالة الجهاز للداشبورد، وتنفذ منع مواقع تجريبي على مستوى DNS.

### النطاق المتفق عليه

- الأدوات ستكون منفصلة حسب نوع الجهاز.
- البداية الحالية على Windows.
- السيرفر يعمل محليا الآن، والاستضافة الأونلاين مؤجلة.
- المتعافي لا يستخدم التيرمينال؛ يتعامل مع `GreenAgent.exe` بالماوس فقط.
- المتعافي يدخل `Activation Token` فقط.
- في المرحلة التجريبية الخروج اليدوي مسموح، لكن يظهر للأدمن كحالة `Exited`.
- منع المواقع الحالي تجريبي عبر DNS.
- الحماية صعبة الإزالة، Windows Service، وInstaller رسمي مؤجلة لمراحل لاحقة.

### البنية الحالية

```text
E:\HABASHY\Python Codes\Green
```

- `server`: سيرفر FastAPI + قاعدة SQLite + داشبورد.
- `agent-windows`: Windows Agent + DNS filter + سكربتات البناء والطوارئ.
- `PROJECT_CONTEXT_AR_EN.md`: ملف التوثيق الحالي بالعربية والإنجليزية.
- `README.md`: ملاحظات تشغيل مختصرة.

### تدفق الاستخدام الحالي

1. الأدمن يشغل السيرفر ويفتح الداشبورد.
2. الأدمن يضيف اسم المتعافي.
3. السيرفر يولد `Device ID` و`Activation Token`.
4. المتعافي يفتح `GreenAgent.exe`.
5. المتعافي يدخل أو يلصق `Activation Token` ويضغط `Activate`.
6. الـ Agent يحفظ بياناته في `%APPDATA%\Green\agent.config.json`.
7. الـ Agent يرسل heartbeat كل 60 ثانية.
8. الأدمن يرى حالة الجهاز في الداشبورد.
9. لتفعيل المنع، يتم الضغط على `Start Blocking` داخل الـ Agent.
10. الـ Agent يشغل DNS filter محلي ويبدأ تسجيل/منع الدومينات.

### حالات الجهاز في الداشبورد

- `Active`: آخر heartbeat منذ أقل من 3 دقائق.
- `Delayed`: آخر heartbeat بين 3 و10 دقائق.
- `No Signal`: آخر heartbeat منذ أكثر من 10 دقائق.
- `Waiting for Install`: الجهاز مسجل ولم يتصل بعد.
- `Exited`: المتعافي ضغط `Exit Agent` والـ Agent أبلغ السيرفر قبل الخروج.

### ما تم تنفيذه

#### Presence Monitor

- سيرفر FastAPI محلي.
- قاعدة بيانات SQLite.
- Dashboard ملون وبسيط.
- تسجيل أجهزة من اسم المتعافي فقط.
- توليد `Device ID` و`Activation Token` تلقائيا.
- تفعيل Agent بتوكن واحد.
- heartbeat كل 60 ثانية.
- استنتاج `No Signal` عند انقطاع الإشارة.

#### Windows Agent

- واجهة `tkinter`.
- زر `Paste` في خانة التوكن.
- دعم اللصق من الكمبيوتر عبر `Ctrl+V` و`Shift+Insert`.
- حفظ config محلي في `%APPDATA%\Green`.
- يعمل كملف واحد `GreenAgent.exe`.
- لا يحتاج المتعافي إلى PowerShell أو Terminal.
- عند الضغط على `X` يختفي فقط ويستمر في الخلفية.
- يوجد tray icon بجانب ساعة Windows لإعادة فتح الواجهة.
- زر `Exit Agent` للخروج التجريبي.
- عند الخروج يرسل حالة `exited` للداشبورد.

#### ملف تنفيذي واحد

تم بناء الـ Agent كملف واحد:

```text
agent-windows/dist/GreenAgent.exe
```

سكربت البناء:

```text
agent-windows/Build-GreenAgent.ps1
```

الملف التنفيذي يطلب صلاحيات Admin لأن تغيير DNS وتشغيل DNS على port 53 يحتاجان ذلك.

#### DNS Blocking

- فلتر DNS محلي داخل `agent-windows/dns_filter.py`.
- يعمل على `127.0.0.1:53`.
- عند `Start Blocking` يتم تغيير DNS الخاص بواجهات الشبكة النشطة إلى `127.0.0.1`.
- الدومينات المحظورة ترجع `0.0.0.0` أو `::`.
- الدومينات المسموحة يتم تمريرها إلى DNS الأصلي للجهاز.
- توجد قوائم مدمجة مبدئية لتصنيفات Social وAdult.
- كل محاولة دومين ترسل للسيرفر كـ domain event.
- تم تحسين مطابقة القوائم الكبيرة: بدلا من المرور على كل الدومينات المحظورة مع كل طلب DNS، يتم فحص لاحقات الدومين المطلوب فقط.
- تم إضافة Allowlist مبدئية لمواقع مهمة مثل YouTube وMSN وMicrosoft وGoogle حتى لا تحجبها القوائم الخارجية بالخطأ.
- تم إيقاف تسجيل الدومينات المسموحة افتراضيا لتقليل الضغط والبطء؛ يتم تسجيل المحجوب فقط.

#### حماية DNS من تعطيل الإنترنت

بعد تجربة أدت إلى توقف الإنترنت بالكامل، أضيفت الحمايات التالية:

- حفظ DNS القديم قبل أي تغيير.
- تمرير الدومينات المسموحة إلى DNS القديم بدلا من الاعتماد على DNS ثابت فقط.
- عند فشل `Start Blocking` في المنتصف، يحاول البرنامج استرجاع DNS.
- عند `Stop Blocking` يتم استرجاع DNS أولا.
- عند `Exit Agent` يتم استرجاع DNS أولا، وإذا فشل الاسترجاع يتم إلغاء الخروج.
- عند فتح البرنامج، لو وجد جلسة حماية قديمة لم تغلق بشكل صحيح، يحاول استرجاع DNS.
- زر `Restore Internet DNS` في الواجهة.
- سكربت طوارئ:

```text
agent-windows/Restore-DNS.ps1
```

#### Blocked Domains من الداشبورد

تمت إضافة قسم:

```text
Blocked Domains
```

يدعم:

- إضافة دومين واحد.
- اختيار تصنيف: `adult`, `social`, `custom`.
- حذف الدومينات.
- لصق قائمة مواقع دفعة واحدة تحت تصنيف واحد.
- تنظيف الإدخال تلقائيا:
  - إزالة `http://` و`https://`.
  - إزالة `www.`.
  - إزالة أي path أو query.
  - قبول السطور أو الفواصل.
  - تجاهل التكرارات.

جدول قاعدة البيانات:

```text
blocked_domains
```

API:

```text
GET /api/blocklist
```

الـ Agent يسحب القائمة عند `Start Blocking` ويحدثها كل 5 دقائق.

#### Remote Blocklists

تمت إضافة قسم جديد في الداشبورد:

```text
Remote Blocklists
```

الغرض منه تحديث قوائم المواقع الإباحية من مصادر أونلاين جاهزة بدل إدخال كل دومين يدويا.

المصادر الافتراضية الحالية:

- `OISD NSFW`
- `BlockListProject Porn`

ما تم تنفيذه:

- جدول جديد في قاعدة البيانات باسم `remote_blocklists`.
- زر `Update` لكل مصدر.
- زر `Update All` لتحديث كل المصادر.
- تنزيل القائمة من الإنترنت.
- دعم صيغ مختلفة للقوائم:
  - دومينات عادية.
  - hosts format مثل `0.0.0.0 example.com`.
  - Adblock Plus format مثل `||example.com^`.
- تنظيف الدومينات قبل الحفظ.
- تجاهل التكرارات.
- حفظ الدومينات في جدول `blocked_domains` تحت تصنيف `adult`.
- عرض آخر وقت فحص، آخر نجاح، عدد الدومينات في القائمة، وعدد الدومينات الجديدة التي تم استيرادها.
- وجود حد أمان لحجم ملف القائمة حتى لا يتجمد السيرفر عند مصدر كبير جدا.
- الداشبورد الرئيسي لا يعرض جدول الدومينات حتى لا يصبح بطيئا.
- يوجد زر `View Domains` يفتح صفحة منفصلة:

```text
/blocked-domains
```

- صفحة الدومينات تدعم pagination واختيار عدد الدومينات في كل صفحة: 25 أو 50 أو 100 أو 200.
- الـ Agent يستلم القائمة كاملة من API حتى لو الداشبورد يعرضها على صفحات.
- بعد استيراد قوائم ضخمة، تمت إضافة database indexes على `blocked_domains.domain` و`blocked_domains.category` لتحسين الأداء.

تمت تجربة التحديث بنجاح:

- `BlockListProject Porn`: وجد حوالي 499 ألف دومين.
- `OISD NSFW`: وجد حوالي 338 ألف دومين.

بعد تحديث القوائم، الـ Agent يستفيد تلقائيا لأنه يسحب نفس endpoint:

```text
GET /api/blocklist
```

لو كان `Start Blocking` مفعلا، تصل القوائم الجديدة عند التحديث الدوري التالي للـ Agent. وللتحديث الفوري يمكن عمل `Stop Blocking` ثم `Start Blocking`.

#### Domain Activity

كان جدول نشاط الدومينات يظهر باستمرار في الصفحة الرئيسية، ثم تم تعديله:

- لم يعد يظهر في الصفحة الرئيسية.
- في جدول `Devices` يوجد عمود `Activity`.
- أمام كل متعافي/جهاز زر `View`.
- الزر يفتح صفحة نشاط خاصة بالجهاز:

```text
/devices/{device_id}/activity
```

الصفحة تعرض:

- الدومين.
- القرار: `allowed` أو `blocked`.
- التصنيف.
- سبب القرار.
- وقت المحاولة.

### أهم الملفات

```text
server/app/main.py
```

يحتوي على:

- FastAPI app.
- إنشاء الجداول.
- `POST /api/activate`.
- `POST /api/heartbeat`.
- `POST /api/domain-event`.
- `GET /api/blocklist`.
- `GET /api/devices`.
- `GET /blocked-domains`.
- `GET /devices/{device_id}/activity`.
- نماذج إضافة وحذف واستيراد الدومينات.

```text
server/app/templates/dashboard.html
```

الداشبورد الرئيسي:

- ملخص الحالات.
- إضافة المتعافين.
- جدول الأجهزة.
- زر `View` لنشاط كل جهاز.
- إدارة `Blocked Domains`.
- استيراد جماعي للدومينات.
- زر `View Domains` لفتح جدول الدومينات عند الحاجة فقط.

```text
server/app/templates/blocked_domains.html
```

صفحة عرض الدومينات المحظورة مع pagination.

```text
server/app/templates/device_activity.html
```

صفحة نشاط الدومينات لجهاز واحد.

```text
server/app/static/styles.css
```

تنسيق الداشبورد والنماذج والجداول.

```text
agent-windows/agent_gui.py
```

واجهة ومنطق الـ Agent:

- التفعيل.
- heartbeat.
- tray icon.
- تشغيل/إيقاف الحظر.
- استرجاع DNS.
- سحب blocklist.

```text
agent-windows/dns_filter.py
```

DNS filter:

- تصنيف الدومينات.
- القوائم المدمجة.
- القوائم الديناميكية القادمة من السيرفر.
- تمرير الطلبات المسموحة إلى upstream DNS.

```text
agent-windows/dist/GreenAgent.exe
```

ملف Agent النهائي للتجربة.

### أوامر التشغيل

تشغيل السيرفر:

```powershell
cd "E:\HABASHY\Python Codes\Green\server"
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

فتح الداشبورد:

```text
http://127.0.0.1:8000
```

تشغيل Agent للمستخدم:

```text
E:\HABASHY\Python Codes\Green\agent-windows\dist\GreenAgent.exe
```

استرجاع DNS يدويا عند الطوارئ:

```powershell
cd "E:\HABASHY\Python Codes\Green\agent-windows"
.\Restore-DNS.ps1
```

### ملاحظات مهمة

- يجب تشغيل `GreenAgent.exe` بصلاحية Admin لتفعيل DNS blocking.
- إذا كان المتصفح يستخدم Secure DNS / DNS over HTTPS فقد يتخطى حظر DNS.
- بعد إضافة دومينات جديدة قد تحتاج إلى `ipconfig /flushdns` أو إغلاق المتصفح وإعادة فتحه.
- القوائم في الداشبورد لا تؤثر إلا عندما يكون الـ Agent في حالة `Start Blocking`.
- إذا توقف الإنترنت، استخدم `Restore Internet DNS` أو `Restore-DNS.ps1`.
- السيرفر ما زال بدون Login.
- لا يوجد Windows Service بعد.
- لا يوجد Installer بعد.
- لا توجد حماية ضد حذف البرنامج بعد.
- لا توجد استضافة أونلاين بعد.

### الخطوات القادمة المقترحة

1. إضافة Login للأدمن.
2. إضافة تحديث تلقائي مجدول لقوائم `Remote Blocklists` كل 24 ساعة.
3. تقليل تسجيل `allowed` أو جعله اختياريا لتقليل الضوضاء.
4. كشف أو تعطيل Secure DNS / DoH في المتصفحات.
5. تحويل Agent إلى Windows Service.
6. عمل Installer.
7. رفع السيرفر أونلاين.
8. إضافة AI classification للدومينات غير المعروفة.
9. دعم Android وiOS لاحقا بطرق مناسبة لكل نظام.

---

## English

### Current Phase

```text
windows-dns-local-proof-of-concept
```

This phase proves the local Windows workflow: admin dashboard, token-based Agent activation, 60-second presence heartbeat, DNS-level blocking, imported/updated adult blocklists, DNS restore safety, and basic false-positive reduction through an Agent allowlist.

### General Goal

`Green` is an early Windows device monitoring and protection system. The long-term goal is to block adult and social media websites across computers and mobile devices. The current version verifies Agent presence, reports device state, and performs experimental DNS-level website blocking.

### Agreed Scope

- Tools will be separate per device type.
- The current implementation targets Windows.
- The server runs locally now; online hosting is planned later.
- The recovering user should not use the terminal; interaction is mouse-only through `GreenAgent.exe`.
- The user enters only an `Activation Token`.
- During the experimental phase, manual exit is allowed and reported to the admin as `Exited`.
- Current website blocking is experimental DNS-level blocking.
- Hard-to-remove protection, Windows Service, and formal installer are future stages.

### Current Structure

```text
E:\HABASHY\Python Codes\Green
```

- `server`: FastAPI + SQLite + Dashboard.
- `agent-windows`: Windows Agent + DNS filter + build/emergency scripts.
- `PROJECT_CONTEXT_AR_EN.md`: current bilingual documentation.
- `README.md`: short running notes.

### Current Flow

1. Admin starts the server and opens the dashboard.
2. Admin adds the recovery/person name.
3. Server generates `Device ID` and `Activation Token`.
4. User opens `GreenAgent.exe`.
5. User enters/pastes the `Activation Token` and clicks `Activate`.
6. Agent stores local config in `%APPDATA%\Green\agent.config.json`.
7. Agent sends heartbeat every 60 seconds.
8. Admin sees device status in the dashboard.
9. To enable blocking, the user clicks `Start Blocking`.
10. The Agent starts a local DNS filter and begins logging/blocking domains.

### Dashboard Status Rules

- `Active`: last heartbeat is less than 3 minutes old.
- `Delayed`: last heartbeat is between 3 and 10 minutes old.
- `No Signal`: last heartbeat is more than 10 minutes old.
- `Waiting for Install`: registered but not activated/connected yet.
- `Exited`: user clicked `Exit Agent` and the Agent reported before closing.

### Implemented Features

#### Presence Monitor

- Local FastAPI server.
- SQLite database.
- Color-based dashboard.
- Device registration by recovery name only.
- Automatic `Device ID` and `Activation Token` generation.
- One-token Agent activation.
- Heartbeat every 60 seconds.
- `No Signal` derived from missing heartbeat.

#### Windows Agent

- `tkinter` GUI.
- `Paste` button for token input.
- `Ctrl+V` and `Shift+Insert` paste support.
- Local config in `%APPDATA%\Green`.
- Single-file `GreenAgent.exe`.
- No terminal required for the user.
- Window close button hides the Agent instead of stopping it.
- Tray icon near the Windows clock.
- Experimental `Exit Agent`.
- On exit, Agent sends `exited` status.

#### Single-File Executable

Current Agent executable:

```text
agent-windows/dist/GreenAgent.exe
```

Build script:

```text
agent-windows/Build-GreenAgent.ps1
```

The executable requests Admin privileges because DNS changes and port 53 require elevation.

#### DNS Blocking

- Local DNS filter in `agent-windows/dns_filter.py`.
- Runs on `127.0.0.1:53`.
- `Start Blocking` changes active network DNS interfaces to `127.0.0.1`.
- Blocked domains return `0.0.0.0` or `::`.
- Allowed domains are forwarded to the computer's previous DNS servers.
- Built-in initial Social and Adult domain lists exist.
- Domain attempts are sent to the server as domain events.
- Large-list matching was optimized: instead of iterating over every blocked domain on each DNS query, the filter checks only the requested domain suffixes.
- A default Allowlist was added for important services such as YouTube, MSN, Microsoft, and Google so remote lists cannot block them by mistake.
- Allowed-domain logging is disabled by default to reduce load; blocked events are still logged.

#### DNS Safety

After a test caused a full internet outage, these protections were added:

- Save previous DNS settings before changes.
- Forward allowed domains to the previous DNS servers, not only a hardcoded DNS server.
- If `Start Blocking` fails halfway, the Agent attempts DNS restore.
- `Stop Blocking` restores DNS first.
- `Exit Agent` restores DNS first; if restore fails, exit is cancelled.
- On startup, the Agent detects stale protection sessions and attempts DNS restore.
- GUI button: `Restore Internet DNS`.
- Emergency script:

```text
agent-windows/Restore-DNS.ps1
```

#### Dashboard-Managed Blocked Domains

Dashboard section:

```text
Blocked Domains
```

Supports:

- Add one domain.
- Choose category: `adult`, `social`, `custom`.
- Delete domains.
- Bulk paste/import domains under one selected category.
- Input cleanup:
  - removes `http://` and `https://`.
  - removes `www.`.
  - removes paths and query strings.
  - accepts newlines or separators.
  - ignores duplicates.

Database table:

```text
blocked_domains
```

API:

```text
GET /api/blocklist
```

The Agent fetches this list when `Start Blocking` is clicked and refreshes it every 5 minutes.

#### Remote Blocklists

A new dashboard section was added:

```text
Remote Blocklists
```

Its purpose is to update adult website domain lists from online sources instead of entering every domain manually.

Current default sources:

- `OISD NSFW`
- `BlockListProject Porn`

Implemented behavior:

- New database table: `remote_blocklists`.
- `Update` button per source.
- `Update All` button for all sources.
- Downloads the remote list from the internet.
- Supports multiple list formats:
  - plain domains.
  - hosts format such as `0.0.0.0 example.com`.
  - Adblock Plus format such as `||example.com^`.
- Normalizes domains before saving.
- Ignores duplicates.
- Saves domains into `blocked_domains` with category `adult`.
- Shows last check time, last success time, domain count, and newly imported count.
- Includes a download size safety limit so a very large source cannot freeze the server.
- The main dashboard does not render the blocked-domain table to keep the page fast.
- A `View Domains` button opens a separate page:

```text
/blocked-domains
```

- The blocked-domains page supports pagination and page sizes: 25, 50, 100, or 200.
- The Agent still receives the full list through the API even though the dashboard displays it page by page.
- After importing large lists, database indexes were added on `blocked_domains.domain` and `blocked_domains.category` for better performance.

Successful test results:

- `BlockListProject Porn`: found about 499k domains.
- `OISD NSFW`: found about 338k domains.

After updating the lists, the Agent benefits automatically because it uses the same endpoint:

```text
GET /api/blocklist
```

If `Start Blocking` is active, the new domains arrive on the Agent's next periodic refresh. For immediate refresh, click `Stop Blocking`, then `Start Blocking`.

#### Domain Activity

Domain activity used to appear on the main dashboard, then was changed:

- It no longer appears on the main dashboard.
- The `Devices` table has an `Activity` column.
- Each device has a `View` link.
- The link opens a device-specific activity page:

```text
/devices/{device_id}/activity
```

The page shows:

- domain.
- decision: `allowed` or `blocked`.
- category.
- reason.
- timestamp.

### Important Files

```text
server/app/main.py
```

Contains:

- FastAPI app.
- table initialization.
- `POST /api/activate`.
- `POST /api/heartbeat`.
- `POST /api/domain-event`.
- `GET /api/blocklist`.
- `GET /api/devices`.
- `GET /blocked-domains`.
- `GET /devices/{device_id}/activity`.
- blocked-domain add/delete/import forms.

```text
server/app/templates/dashboard.html
```

Main dashboard:

- status summary.
- recovery registration.
- devices table.
- per-device `View` activity link.
- `Blocked Domains` management.
- bulk domain import.
- `View Domains` button to open the domain table only when needed.

```text
server/app/templates/blocked_domains.html
```

Paginated blocked-domain listing page.

```text
server/app/templates/device_activity.html
```

Per-device domain activity page.

```text
server/app/static/styles.css
```

Dashboard styling.

```text
agent-windows/agent_gui.py
```

Agent GUI and logic:

- activation.
- heartbeat.
- tray icon.
- start/stop blocking.
- DNS restore.
- blocklist fetching.

```text
agent-windows/dns_filter.py
```

DNS filter:

- domain classification.
- built-in lists.
- dynamic admin blocklist.
- upstream DNS forwarding.

```text
agent-windows/dist/GreenAgent.exe
```

Current Agent executable for testing.

### Run Commands

Start server:

```powershell
cd "E:\HABASHY\Python Codes\Green\server"
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open dashboard:

```text
http://127.0.0.1:8000
```

Run Agent:

```text
E:\HABASHY\Python Codes\Green\agent-windows\dist\GreenAgent.exe
```

Emergency DNS restore:

```powershell
cd "E:\HABASHY\Python Codes\Green\agent-windows"
.\Restore-DNS.ps1
```

### Important Notes

- `GreenAgent.exe` must run as Admin for DNS blocking.
- Browser Secure DNS / DNS over HTTPS can bypass DNS blocking.
- After adding domains, `ipconfig /flushdns` or browser restart may be needed.
- Dashboard lists only affect devices while `Start Blocking` is active.
- If internet breaks, use `Restore Internet DNS` or `Restore-DNS.ps1`.
- No admin login yet.
- No Windows Service yet.
- No installer yet.
- No anti-uninstall/tamper protection yet.
- No online hosting yet.

### Suggested Next Steps

1. Add admin login.
2. Add automatic scheduled updates for `Remote Blocklists` every 24 hours.
3. Reduce or make optional `allowed` domain logging.
4. Detect or disable browser Secure DNS / DoH.
5. Convert Agent to Windows Service.
6. Create installer.
7. Deploy server online.
8. Add AI classification for unknown domains.
9. Later support Android and iOS with OS-appropriate methods.
