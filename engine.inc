#pragma mark - السرعة الحية: تأخير ثم لحاق (WSOLA لكل متكلم، النغمة محفوظة)
// الصوت المباشر لا يمكن تسريعه فوق سرعة وصوله. الحل: "تجميع" تأخير قصير بصمت ثم تشغيل المتجمّع مسرّعاً
// (x1.5..x4) بنغمة طبيعية حتى نلحق البث الحي، وبعدها يرجع تلقائياً 1x بلا تقطيع.
// المحرك يُختبر بمعزل عن اللعبة (انظر README) ولا يمسّ إلا صوت المتكلمين القادم لجهازك.
#define DSL_MAXHS 512
#define DSL_OUTQ  16384

typedef struct {
    int sr, Hs, N, D;
    int16_t *ring; long ringSize;
    long wpos; double rp; long last;
    int state;                    // 0 = تشغيل/لحاق، 1 = تجميع (صمت)
    long accumT;
    float accum[2 * DSL_MAXHS];
    int16_t outq[DSL_OUTQ]; int oHead, oCount;
    float lastSpeed;
    int seenRestart, seenLive;
} DSLiveEng;

static inline int16_t DSLAt(DSLiveEng *e, long pos) {
    long m = pos % e->ringSize; if (m < 0) m += e->ringSize;
    return e->ring[m];
}

static void DSLEngInit(DSLiveEng *e, int sr) {
    if (e->ring) free(e->ring);
    memset(e, 0, sizeof *e);
    e->sr = sr;
    e->Hs = sr / 100; if (e->Hs > DSL_MAXHS) e->Hs = DSL_MAXHS; if (e->Hs < 80) e->Hs = 80;
    e->N = 2 * e->Hs; e->D = e->Hs / 2;
    e->ringSize = (long)sr * 45;
    e->ring = (int16_t *)calloc((size_t)e->ringSize, sizeof(int16_t));
    e->last = -1; e->lastSpeed = 1.0f;
    e->seenRestart = gLiveRestartGen; e->seenLive = gLiveLiveGen;
}

static void DSLGoLive(DSLiveEng *e) {
    long keep = (long)e->N + e->D + 2L * e->Hs;
    long rp = e->wpos - keep; if (rp < 0) rp = 0;
    e->rp = (double)rp; e->last = -1; e->state = 0;
    e->oHead = 0; e->oCount = 0;
    memset(e->accum, 0, sizeof e->accum);
}

static void DSLStartAccum(DSLiveEng *e, int delaySec) {
    if (delaySec < 3) delaySec = 3; if (delaySec > 40) delaySec = 40;
    e->accumT = (long)delaySec * e->sr;
    e->rp = (double)e->wpos; e->last = -1; e->state = 1;
}

static int DSLHop(DSLiveEng *e, float speed) {
    if (e->oCount + e->Hs > DSL_OUTQ) return 0;
    if (e->state == 1) {
        if (e->wpos - (long)e->rp >= e->accumT) e->state = 0; else return 0;
    }
    long backlog = e->wpos - (long)e->rp - (e->N + e->D);
    if (backlog < 0) return 0;
    float eff = speed;
    if (eff > 1.0f && backlog < (long)(e->Hs * eff) + e->Hs) eff = 1.0f;   // وصلنا للبث الحي
    long s = (long)e->rp;
    if (e->last >= 0 && s != e->last + e->Hs) {   // محاذاة WSOLA: أفضل إزاحة تتصل بسلاسة بالمقطع السابق
        long t = e->last + e->Hs, bs = s; double best = -1e30;
        for (long d = -e->D; d <= e->D; d += 2) {
            long c = s + d;
            if (c < 0 || c + e->N > e->wpos) continue;
            double sum = 0, en = 1e-9;
            for (int j = 0; j < e->Hs; j += 4) {
                double a = DSLAt(e, t + j), b = DSLAt(e, c + j);
                sum += a * b; en += b * b;
            }
            double score = sum / sqrt(en);
            if (score > best) { best = score; bs = c; }
        }
        s = bs;
    }
    for (int i = 0; i < e->N; i++) {
        float w = (i < e->Hs) ? (float)i / e->Hs : (float)(e->N - i) / e->Hs;
        e->accum[i] += DSLAt(e, s + i) * w;
    }
    for (int i = 0; i < e->Hs; i++) {
        float v = e->accum[i];
        if (v > 32767.f) v = 32767.f; if (v < -32768.f) v = -32768.f;
        e->outq[(e->oHead + e->oCount + i) % DSL_OUTQ] = (int16_t)v;
    }
    e->oCount += e->Hs;
    memmove(e->accum, e->accum + e->Hs, e->Hs * sizeof(float));
    memset(e->accum + e->Hs, 0, e->Hs * sizeof(float));
    e->last = s; e->rp += e->Hs * eff;
    return 1;
}

// يعالج n عيّنة mono في المكان (buf). يُستدعى من خيط صوت Agora.
static void DSLProcess(DSLiveEng *e, int16_t *buf, int n, float speed, int delaySec) {
    if (e->seenLive != gLiveLiveGen) { e->seenLive = gLiveLiveGen; DSLGoLive(e); }
    if (e->seenRestart != gLiveRestartGen) {
        e->seenRestart = gLiveRestartGen;
        if (speed > 1.0f) DSLStartAccum(e, delaySec); else DSLGoLive(e);
    }
    if (speed != e->lastSpeed) {
        e->lastSpeed = speed;
        if (speed <= 1.0f) DSLGoLive(e);
        else if (e->state == 0 && (e->wpos - (long)e->rp - (e->N + e->D)) < e->sr) DSLStartAccum(e, delaySec);
        // لو يوجد تراكم أكثر من ثانية (نلحق الآن): نكمل بالسرعة الجديدة بدون إعادة تجميع
    }
    for (int i = 0; i < n; i++) e->ring[(e->wpos + i) % e->ringSize] = buf[i];
    e->wpos += n;
    if (e->wpos - (long)e->rp > e->ringSize - 4L * e->Hs) e->rp = (double)(e->wpos - e->ringSize / 2);
    for (int g = 0; g < 16 && e->oCount < n; g++) if (!DSLHop(e, speed)) break;
    int take = e->oCount < n ? e->oCount : n;
    for (int i = 0; i < take; i++) buf[i] = e->outq[(e->oHead + i) % DSL_OUTQ];
    for (int i = take; i < n; i++) buf[i] = 0;
    e->oHead = (e->oHead + take) % DSL_OUTQ; e->oCount -= take;

    if (e->state == 1) {                                   // حالة العرض في المنيو الصغير
        gLiveMode = 1;
        gLiveA = (int)((e->wpos - (long)e->rp) * 1000L / e->sr);
        gLiveB = (int)(e->accumT * 1000L / e->sr);
    } else {
        long bl = e->wpos - (long)e->rp - (e->N + e->D);
        if (speed > 1.0f && bl > 2L * e->Hs) { gLiveMode = 2; gLiveA = (int)(bl * 1000L / e->sr); gLiveB = 0; }
        else { gLiveMode = 0; gLiveA = 0; gLiveB = 0; }
    }
}

static DSLiveEng *gLiveEngs[8];
static NSUInteger gLiveUids[8];
static int gLiveCount = 0, gLiveNext = 0;

static DSLiveEng *DSLEngForUid(NSUInteger uid, int sr) {
    if (sr < 8000 || sr > 48000) return NULL;
    int idx = -1;
    for (int i = 0; i < gLiveCount; i++) if (gLiveUids[i] == uid) { idx = i; break; }
    if (idx < 0) {
        if (gLiveCount < 8) idx = gLiveCount++;
        else { idx = gLiveNext; gLiveNext = (gLiveNext + 1) % 8; }
        if (!gLiveEngs[idx]) gLiveEngs[idx] = (DSLiveEng *)calloc(1, sizeof(DSLiveEng));
        if (!gLiveEngs[idx]) return NULL;
        gLiveUids[idx] = uid;
        DSLEngInit(gLiveEngs[idx], sr);
    }
    DSLiveEng *e = gLiveEngs[idx];
    if (e->sr != sr) DSLEngInit(e, sr);
    return e->ring ? e : NULL;
}

