#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
typedef unsigned long NSUInteger;
static volatile int gLiveRestartGen = 0, gLiveLiveGen = 0, gLiveMode = 0, gLiveA = 0, gLiveB = 0;
#define MAXN 100000
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#include "engine.inc"

// عدّ عبور الصفر (تقدير النغمة) لمقطع
static double zcr(int16_t *x, int n) { int z = 0; for (int i = 1; i < n; i++) if ((x[i-1] < 0) != (x[i] < 0)) z++; return z; }
static double rms(int16_t *x, int n) { double s = 0; for (int i = 0; i < n; i++) s += (double)x[i] * x[i]; return sqrt(s / (n ? n : 1)); }

int main(void) {
    const int sr = 48000, frame = 480, seconds = 40;
    DSLiveEng *e = DSLEngForUid(7, sr);
    int total = sr * seconds;
    int16_t *in = malloc(total * 2), *out = malloc(total * 2);
    // إشارة "كلام" تجريبية: 220Hz مع تعديل سعة 3Hz (تتكرر النبضات)
    for (int i = 0; i < total; i++) {
        double t = (double)i / sr;
        double env = 0.5 + 0.5 * sin(2 * M_PI * 3 * t);
        in[i] = (int16_t)(12000 * env * sin(2 * M_PI * 220 * t));
    }
    memcpy(out, in, total * 2);
    float speed = 1.0f; int delay = 10;
    int modeHist[3] = {0,0,0};
    for (int f = 0; f * frame < total; f++) {
        double now = (double)(f * frame) / sr;
        if (now >= 5.0 && speed == 1.0f) speed = 2.0f;            // عند الثانية 5 نختار x2 (تأخير 10ث)
        DSLProcess(e, out + f * frame, frame, speed, delay);
        modeHist[gLiveMode]++;
        if (f % 500 == 0) printf("t=%5.1fs mode=%d A=%dms B=%dms\n", now, gLiveMode, gLiveA, gLiveB);
    }
    // تحليل: صمت التجميع 5..15، ثم لحاق، ثم 1x
    printf("\nrms قبل التسريع 1..4s : %.0f (متوقع ~8500)\n", rms(out + sr, 3 * sr));
    printf("rms أثناء التجميع 6..14s: %.0f (متوقع ~0)\n", rms(out + 6 * sr, 8 * sr));
    // موضع أول صوت بعد الثانية 5
    int first = -1; for (int i = 5 * sr; i < total; i++) if (abs(out[i]) > 2000) { first = i; break; }
    printf("أول صوت بعد التجميع عند t=%.2fs (متوقع ~15s)\n", (double)first / sr);
    // مدة اللحاق: بعد الصوت الأول، نقيس متى يرجع التسريع لـ1x عبر حالة المحرك
    printf("إطارات تجميع=%d لحاق=%d مباشر=%d\n", modeHist[1], modeHist[2], modeHist[0]);
    // النغمة أثناء اللحاق (يجب أن تبقى ~220Hz)
    int cs = first + sr / 2, cn = 2 * sr;
    printf("نغمة اللحاق ~ %.1f Hz (متوقع ~220)\n", zcr(out + cs, cn) / 2.0 / ((double)cn / sr));
    int ls = 35 * sr, ln = 3 * sr;
    printf("نغمة بعد اللحاق ~ %.1f Hz، rms=%.0f\n", zcr(out + ls, ln) / 2.0 / ((double)ln / sr), rms(out + ls, ln));
    // سرعة التقدّم: الدورة 3Hz تُسرَّع x2 أثناء اللحاق
    int peaks = 0; int16_t *p = out + first; int span = 4 * sr; double env = 0, prev = 0, prev2 = 0;
    for (int i = 0; i + 480 < span; i += 480) { env = rms(p + i, 480); if (prev > env && prev > prev2 && prev > 4000) peaks++; prev2 = prev; prev = env; }
    printf("قمم السعة في 4 ثوانٍ أثناء اللحاق: %d (1x≈12، x2≈24)\n", peaks);
    // مقارنة: عدّة اختبارات للأمان (لا انفجار/NaN)
    int bad = 0; for (int i = 0; i < total; i++) if (out[i] == -32768) bad++;
    printf("عيّنات مقطوعة: %d\n", bad);
    return 0;
}
