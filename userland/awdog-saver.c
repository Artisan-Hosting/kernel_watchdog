#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define AWDOG_DEFAULT_SOURCE "awdog-live-trip"
#define AWDOG_MAX_ATTRS 32
#define AWDOG_MAX_KEY_LEN 64
#define AWDOG_MAX_VAL_LEN 256

struct awdog_attr {
  char key[AWDOG_MAX_KEY_LEN];
  char value[AWDOG_MAX_VAL_LEN];
};

struct awdog_attr_set {
  struct awdog_attr items[AWDOG_MAX_ATTRS];
  size_t count;
};

static void awdog_usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [--phase PHASE] [--reason REASON] [--raw-line LINE] "
          "[--source SOURCE] [MESSAGE]\n",
          prog);
}

static bool awdog_streq(const char *a, const char *b) {
  return a && b && strcmp(a, b) == 0;
}

static bool awdog_contains_icase(const char *text, const char *needle) {
  size_t nlen;
  const char *p;

  if (!text || !needle)
    return false;

  nlen = strlen(needle);
  if (!nlen)
    return false;

  for (p = text; *p; ++p) {
    if (strncasecmp(p, needle, nlen) == 0)
      return true;
  }
  return false;
}

static void awdog_trim_quotes(char *value) {
  size_t len;

  if (!value)
    return;

  len = strlen(value);
  if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
    memmove(value, value + 1, len - 2);
    value[len - 2] = '\0';
  }
}

static bool awdog_is_valid_key(const char *key) {
  const unsigned char *p = (const unsigned char *)key;

  if (!key || !*key)
    return false;

  for (; *p; ++p) {
    if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
      return false;
  }
  return true;
}

static void awdog_add_attr(struct awdog_attr_set *set, const char *key,
                           const char *value) {
  struct awdog_attr *dst;

  if (!set || !key || !value)
    return;

  if (!awdog_is_valid_key(key))
    return;

  if (set->count >= AWDOG_MAX_ATTRS)
    return;

  dst = &set->items[set->count++];
  snprintf(dst->key, sizeof(dst->key), "%s", key);
  snprintf(dst->value, sizeof(dst->value), "%s", value);
}

static const char *awdog_find_attr(const struct awdog_attr_set *set,
                                   const char *key) {
  size_t i;

  if (!set || !key)
    return NULL;

  for (i = 0; i < set->count; ++i) {
    if (strcmp(set->items[i].key, key) == 0)
      return set->items[i].value;
  }
  return NULL;
}

static bool awdog_reserved_key(const char *key) {
  return awdog_streq(key, "phase") || awdog_streq(key, "reason") ||
         awdog_streq(key, "raw_line") || awdog_streq(key, "source") ||
         awdog_streq(key, "ingested_at");
}

static void awdog_parse_attrs(const char *input, struct awdog_attr_set *attrs) {
  char *copy;
  char *saveptr = NULL;
  char *token;

  if (!input || !attrs)
    return;

  copy = strdup(input);
  if (!copy)
    return;

  token = strtok_r(copy, " \t\r\n", &saveptr);
  while (token) {
    char *sep;

    if (!strcmp(token, "AWDOG_TRIP")) {
      token = strtok_r(NULL, " \t\r\n", &saveptr);
      continue;
    }

    sep = strchr(token, '=');
    if (sep) {
      *sep = '\0';
      ++sep;
      awdog_trim_quotes(sep);
      awdog_add_attr(attrs, token, sep);
    }

    token = strtok_r(NULL, " \t\r\n", &saveptr);
  }

  free(copy);
}

static const char *awdog_classify_phase(const char *reason) {
  if (awdog_contains_icase(reason, "test"))
    return "test_mode_trip";
  if (awdog_contains_icase(reason, "reboot"))
    return "reboot_requested";
  if (awdog_contains_icase(reason, "verify") ||
      awdog_contains_icase(reason, "heartbeat") ||
      awdog_contains_icase(reason, "timeout"))
    return "heartbeat_rejected";
  return "tamper_tripped";
}

static void awdog_json_string(FILE *out, const char *text) {
  const unsigned char *p = (const unsigned char *)(text ? text : "");

  fputc('"', out);
  while (*p) {
    switch (*p) {
    case '\\':
      fputs("\\\\", out);
      break;
    case '"':
      fputs("\\\"", out);
      break;
    case '\n':
      fputs("\\n", out);
      break;
    case '\r':
      fputs("\\r", out);
      break;
    case '\t':
      fputs("\\t", out);
      break;
    default:
      if (*p < 0x20)
        fprintf(out, "\\u%04x", *p);
      else
        fputc(*p, out);
      break;
    }
    ++p;
  }
  fputc('"', out);
}

static int awdog_write_all(int fd, const char *buf, size_t len) {
  size_t offset = 0;

  while (offset < len) {
    ssize_t n = write(fd, buf + offset, len - offset);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    offset += (size_t)n;
  }
  return 0;
}

static char *awdog_join_args(char **argv, int start, int argc) {
  size_t total = 0;
  int i;
  char *joined;
  char *out;

  if (start >= argc)
    return strdup("unknown");

  for (i = start; i < argc; ++i)
    total += strlen(argv[i]) + 1;

  joined = calloc(1, total + 1);
  if (!joined)
    return NULL;

  out = joined;
  for (i = start; i < argc; ++i) {
    size_t len = strlen(argv[i]);
    memcpy(out, argv[i], len);
    out += len;
    if (i != argc - 1)
      *out++ = ' ';
  }
  *out = '\0';
  return joined;
}

int main(int argc, char **argv) {
  const char *phase_arg = NULL;
  const char *reason_arg = NULL;
  const char *raw_line_arg = NULL;
  const char *source_arg = NULL;
  const char *phase;
  const char *reason;
  const char *raw_line;
  const char *source;
  const char *env_source;
  const char *env_pmsg_path;
  const char *pmsg_path;
  struct awdog_attr_set attrs = {0};
  char *message = NULL;
  char raw_line_buf[512];
  char *payload = NULL;
  size_t payload_len = 0;
  FILE *mem = NULL;
  int fd = -1;
  int i;
  time_t now = time(NULL);
  int rc = 1;
  bool first_attr = true;

  for (i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--phase")) {
      if (i + 1 >= argc) {
        awdog_usage(argv[0]);
        goto out;
      }
      phase_arg = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--reason")) {
      if (i + 1 >= argc) {
        awdog_usage(argv[0]);
        goto out;
      }
      reason_arg = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--raw-line")) {
      if (i + 1 >= argc) {
        awdog_usage(argv[0]);
        goto out;
      }
      raw_line_arg = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--source")) {
      if (i + 1 >= argc) {
        awdog_usage(argv[0]);
        goto out;
      }
      source_arg = argv[++i];
      continue;
    }
    if (!strcmp(argv[i], "--")) {
      ++i;
      break;
    }
    if (!strncmp(argv[i], "--", 2)) {
      awdog_usage(argv[0]);
      goto out;
    }
    break;
  }

  message = awdog_join_args(argv, i, argc);
  if (!message) {
    fprintf(stderr, "awdog-saver: failed to allocate message\n");
    goto out;
  }

  if (!*message && reason_arg) {
    free(message);
    message = strdup(reason_arg);
    if (!message)
      goto out;
  }

  awdog_parse_attrs(message, &attrs);

  reason = reason_arg ? reason_arg : awdog_find_attr(&attrs, "reason");
  if (!reason || !*reason)
    reason = message;
  if (!reason || !*reason)
    reason = "unknown";

  phase = phase_arg ? phase_arg : awdog_find_attr(&attrs, "phase");
  if (!phase || !*phase)
    phase = awdog_classify_phase(reason);

  raw_line = raw_line_arg ? raw_line_arg : awdog_find_attr(&attrs, "raw_line");
  if (!raw_line || !*raw_line) {
    snprintf(raw_line_buf, sizeof(raw_line_buf), "awdog: tamper tripped: %s",
             reason);
    raw_line = raw_line_buf;
  }

  env_source = getenv("AWDOG_TRIP_SOURCE");
  source = source_arg ? source_arg : awdog_find_attr(&attrs, "source");
  if (!source || !*source)
    source = env_source;
  if (!source || !*source)
    source = AWDOG_DEFAULT_SOURCE;

  env_pmsg_path = getenv("AWDOG_PMSG_PATH");
  pmsg_path = env_pmsg_path;
  if (!pmsg_path || !*pmsg_path)
    pmsg_path = "/dev/pmsg0";

  mem = open_memstream(&payload, &payload_len);
  if (!mem) {
    fprintf(stderr, "awdog-saver: open_memstream failed: %s\n",
            strerror(errno));
    goto out;
  }

  fputs("{\"ingested_at\":", mem);
  fprintf(mem, "%lld", (long long)now);
  fputs(",\"source\":", mem);
  awdog_json_string(mem, source);
  fputs(",\"phase\":", mem);
  awdog_json_string(mem, phase);
  fputs(",\"reason\":", mem);
  awdog_json_string(mem, reason);
  fputs(",\"raw_line\":", mem);
  awdog_json_string(mem, raw_line);
  fputs(",\"attributes\":{", mem);
  for (size_t a = 0; a < attrs.count; ++a) {
    if (awdog_reserved_key(attrs.items[a].key))
      continue;
    if (!first_attr)
      fputc(',', mem);
    awdog_json_string(mem, attrs.items[a].key);
    fputc(':', mem);
    awdog_json_string(mem, attrs.items[a].value);
    first_attr = false;
  }
  fputs("}}", mem);

  if (fclose(mem) != 0) {
    fprintf(stderr, "awdog-saver: finalize payload failed: %s\n",
            strerror(errno));
    mem = NULL;
    goto out;
  }
  mem = NULL;

  if (env_pmsg_path && *env_pmsg_path)
    fd = open(pmsg_path, O_WRONLY | O_CLOEXEC | O_APPEND | O_CREAT, 0644);
  else
    fd = open(pmsg_path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "awdog-saver: open %s failed: %s\n", pmsg_path,
            strerror(errno));
    goto out;
  }

  if (awdog_write_all(fd, payload, payload_len) != 0 ||
      awdog_write_all(fd, "\n", 1) != 0) {
    fprintf(stderr, "awdog-saver: write to %s failed: %s\n", pmsg_path,
            strerror(errno));
    goto out;
  }

  rc = 0;

out:
  if (fd >= 0)
    close(fd);
  if (mem)
    fclose(mem);
  free(payload);
  free(message);
  return rc;
}
