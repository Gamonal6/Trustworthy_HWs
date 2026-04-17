// TGDH - Part 1: Setup
// builds the key tree from n seeds and writes the group key + all blinded keys

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

static char *slurp(const char *fn) {
    FILE *f = fopen(fn, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(sz + 1);
    size_t n = fread(b, 1, sz, f);
    b[n] = 0;
    fclose(f);
    while (n && (b[n-1]=='\n' || b[n-1]=='\r' || b[n-1]==' ' || b[n-1]=='\t'))
        b[--n] = 0;
    return b;
}

// pad to 256 uppercase hex chars (1024-bit p)
static char *hex256(const BIGNUM *bn) {
    char *raw = BN_bn2hex(bn);
    int len = (int)strlen(raw);
    char *out = malloc(257);
    int pad = 256 - len;
    if (pad < 0) pad = 0;
    memset(out, '0', pad);
    memcpy(out + pad, raw, len);
    out[256] = 0;
    OPENSSL_free(raw);
    return out;
}

typedef struct Node {
    BIGNUM *K, *BK;
    struct Node *l, *r;
    int leaf;
} Node;

static Node *mk(int leaf) {
    Node *n = calloc(1, sizeof(Node));
    n->K = BN_new();
    n->BK = BN_new();
    n->leaf = leaf;
    return n;
}

static void kill_tree(Node *n) {
    if (!n) return;
    kill_tree(n->l); kill_tree(n->r);
    BN_free(n->K); BN_free(n->BK);
    free(n);
}

// left-heavy split: left = ceil(n/2), right = floor(n/2)
static Node *build(BIGNUM **s, int off, int n, const BIGNUM *p, const BIGNUM *g, BN_CTX *ctx) {
    if (n == 1) {
        Node *x = mk(1);
        BN_copy(x->K, s[off]);
        BN_mod_exp(x->BK, g, x->K, p, ctx);
        return x;
    }
    int ln = (n + 1) / 2;
    Node *L = build(s, off, ln, p, g, ctx);
    Node *R = build(s, off + ln, n - ln, p, g, ctx);
    Node *P = mk(0);
    P->l = L; P->r = R;
    BN_mod_exp(P->K, L->BK, R->K, p, ctx);   // K = BK_left ^ K_right mod p
    BN_mod_exp(P->BK, g, P->K, p, ctx);
    return P;
}

static void leaves_lr(Node *n, Node **out, int *i) {
    if (!n) return;
    if (n->leaf) { out[(*i)++] = n; return; }
    leaves_lr(n->l, out, i);
    leaves_lr(n->r, out, i);
}

static void internals_post(Node *n, Node **out, int *i) {
    if (!n || n->leaf) return;
    internals_post(n->l, out, i);
    internals_post(n->r, out, i);
    out[(*i)++] = n;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s p.txt g.txt seed0 [seed1 ...]\n", argv[0]);
        return 1;
    }
    int n = argc - 3;

    char *ph = slurp(argv[1]);
    char *gh = slurp(argv[2]);
    if (!ph || !gh) { fprintf(stderr, "setup: missing DH params\n"); return 1; }

    BIGNUM *p = NULL, *g = BN_new();
    BN_hex2bn(&p, ph);
    BN_dec2bn(&g, gh);              // g is "2" in decimal
    BN_CTX *ctx = BN_CTX_new();

    // K_leaf_i = SHA256(seed_i)
    BIGNUM **secrets = calloc(n, sizeof(BIGNUM *));
    for (int i = 0; i < n; i++) {
        char *sd = slurp(argv[3 + i]);
        if (!sd) { fprintf(stderr, "setup: seed file %d missing\n", i); return 1; }
        unsigned char d[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)sd, strlen(sd), d);
        secrets[i] = BN_bin2bn(d, SHA256_DIGEST_LENGTH, NULL);
        free(sd);
    }

    Node *root = build(secrets, 0, n, p, g, ctx);

    // group key
    char *gk = hex256(root->K);
    FILE *f = fopen("group_key_setup.txt", "w");
    fwrite(gk, 1, 256, f);
    fclose(f);
    free(gk);

    // blinded keys: all leaves (L->R), then internals (post-order)
    int total = 2 * n - 1;
    Node **all = calloc(total, sizeof(Node *));
    int k = 0;
    leaves_lr(root, all, &k);
    internals_post(root, all, &k);

    f = fopen("blinded_keys_setup.txt", "w");
    for (int i = 0; i < k; i++) {
        char *h = hex256(all[i]->BK);
        fwrite(h, 1, 256, f);
        fputc('\n', f);
        free(h);
    }
    fclose(f);

    free(all);
    kill_tree(root);
    for (int i = 0; i < n; i++) BN_free(secrets[i]);
    free(secrets);
    BN_free(p); BN_free(g);
    BN_CTX_free(ctx);
    free(ph); free(gh);
    return 0;
}
