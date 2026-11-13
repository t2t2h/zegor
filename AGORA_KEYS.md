# مفاتيح Agora الموجودة داخل AgoraRtcKit (IPA يلا لودو 4.6.0)

الأسماء مستخرجة من نصوص الثنائي فقط. **المعاني والقيم تخمين من الأسماء وغير موثقة.**
جرّبها واحداً واحداً عبر `Documents/AflatoonSuite/agora_params.json`، مثل: `{"che.audio.neteq.force_stretch": true}`.
زر القائمة «تقليل تأخير الصوت» يعرض بعد الضغط «قبلها Agora: X من Y» (القيمة المرجعة 0 = نجاح).

## تُستخدم تلقائياً بالمستويات
| المفتاح | قيمة | المستوى | المعنى المتوقع |
|---|---|---|---|
| rtc.min_playout_delay | 0 | 1+ | أقل تأخير تشغيل (مللي ثانية) |
| rtc.min_playout_delay_speaker | 0 | 1+ | نفسه للمتكلمين |
| che.audio.neteq.fast_accelerate | true | 1+ | تسريع سريع داخل المخزن |
| che.audio.neteq.acceleration_percent | 50 / 80 / 100 | 1 / 2 / 3+ | نسبة التسريع |
| rtc.max_playout_delay | 300 / 150 | 2 / 3+ | سقف تأخير المخزن (الحد الأعلى 4000) |
| rtc.audience_latency_level | 2 | 2+ | أقل تأخير للمستمع (قنوات البث الحي فقط) |
| che.audio.follow_system_io_buffer_duration | true | 2+ | يتبع مخزن النظام |
| che.audio.neteq.deceleration_percent | 0 | 4 | لا تبطّئ التشغيل |
| che.audio.neteq.force_stretch | true | 4 | يجبر الضغط الزمني |
| che.audio.neteq.accelerate.opt.enable | true | 4 | تسريع محسّن |
| che.audio.neteq.burst_max_limit_jitter_ms | 150 | 4 | سقف الجيتر وقت الاضطراب |
| che.audio.extra_playout_latency | 0 | 4 | بدون تأخير إضافي |
| che.audio.lowlatencycapture | true | 4 | التقاط منخفض التأخير |
| rtc.audience_low_latency / rtc.audience_ultra_low_latency | true | 4 | وضع المستمع منخفض التأخير |

## للتجربة اليدوية (غير مستخدمة)
- NetEQ: `accelerate.min_future_ms`, `accelerate.upper_bound`, `accelerate.window_size`, `accelerate.opt.energy_threshold`, `acceleration_percent_internal`, `deceleration_percent_internal`, `delay_tune`, `pre_buffer`, `pre_buffer_max_delay`, `target_level_improve`, `target_level_set_improve`, `improve_targetlevel_strategy`, `max_packets`, `max_number_packets`, `max_peak_detector`, `multi_plc`, `opus_plc`, `burst_audience_factor`, `burst_comb_window_second`, `burst_control_window_ms`, `burst_freezing_num_threshold`, `burst_jitter_improve_strategy`, `burst_peak_num_threshold`, `burst_peak_trend_increased_threshold`, `burst_platform_ms`, `burst_trend_threshold` (كلها تبدأ بـ `che.audio.neteq.`).
- أخرى: `che.audio.playoutBufferLength`, `che.audio.min.iobuffer.duration`, `che.audio.dtx.mode`, `rtc.audio.dtx`, `rtc.channel.audience_latency_level`.
- تحذير: قيم خاطئة قد تسبب تقطيعاً أو صمتاً. للرجوع: امسح المفتاح من الملف أو اضبطه `{}` وأعد فتح اللعبة.

## المستوى «الكل»
يرسل 44 مفتاحاً دفعة وحدة (الجدول `kAgoraAllKeys` بـ Tweak.xm): 23 اتجاهها واضح، و21 استكشافية قيمها تخمين (مثل `burst_*` و`max_packets`). قيم المفاتيح الاستكشافية ممكن تضر جودة الصوت، فعدّلها من الجدول لو لقيت واحد يسبب مشكلة. استبعدت `neteq.dump` و`neteq.dump_path` لأنها تكتب ملفات تشخيص.

## مفاتيح Zego (المستوى «الكل»)
التطبيق يحوي `ZegoLiveRoom.framework` وغلافاً اسمه `ZegoLiveRoomEngine` داخل YLRoomKit (لغرف تشتغل بـ Zego). تُرسل بصيغة `key=value` عبر `+[ZegoLiveRoomApi setConfig:]` مبكراً عند تشغيل اللعبة، لأن Zego يقرأها عند التهيئة. الدالة لا ترجع نتيجة، فما في عدّاد قبول لها.

| المفتاح | القيمة | المعنى المتوقع |
|---|---|---|
| enable_play_ultra_low_latency | true | تشغيل بأقل تأخير |
| enable_ultra_low_latency | true | وضع أقل تأخير عام |
| prefer_play_ultra_source | 1 | تفضيل مصدر التشغيل منخفض التأخير |
| audio_jitter_break_threshold_ms | 200 | حد قطع الجيتر (أقل = تأخير أقل) |
| jitter_level_compensation | 0 | بدون تعويض جيتر إضافي |
| play_buffer_level_ms_for_cdn_stream | 0 | مخزن التشغيل لبث CDN |
| play_buffer_max_cache_interval_ms | 200 | أقصى تخزين لبث CDN |

الأسماء من نصوص المكتبة فقط، والقيم تخمين. بعضها (CDN) ما يخص غرف الصوت العادية.
