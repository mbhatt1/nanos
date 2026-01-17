/*
 * Authority Kernel - Policy Parsing Unit Tests
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Tests for JSON policy parsing, policy loading, and validation.
 * These tests run on the host without booting the unikernel.
 */

#include <runtime.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

/* Test assertion macros */
#define test_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s at %s:%d\n", #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

#define test_assert_msg(expr, msg) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s - %s at %s:%d\n", msg, #expr, __FILE__, __LINE__); \
        return false; \
    } \
} while (0)

/* ============================================================
 * MINIMAL JSON PARSER FOR TESTING
 * ============================================================
 * This is a simplified JSON parser for policy testing.
 * In production, the runtime's json parser is used.
 */

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value json_value;

struct json_value {
    json_type type;
    union {
        boolean bool_val;
        s64 num_val;
        struct {
            char *str;
            size_t len;
        } string;
        struct {
            json_value **items;
            size_t count;
        } array;
        struct {
            char **keys;
            json_value **values;
            size_t count;
        } object;
    } data;
};

/* Forward declarations */
static json_value *json_parse(const char *json, size_t len, const char **error);
static void json_free(json_value *val);
static json_value *json_get(json_value *obj, const char *key);
static const char *json_get_string(json_value *obj, const char *key);
static json_value *json_get_array(json_value *obj, const char *key);

/* Simple memory allocator for testing */
static void *test_alloc(size_t size)
{
    return malloc(size);
}

static void test_free(void *ptr)
{
    free(ptr);
}

/* Skip whitespace */
static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/* Parse string value */
static json_value *parse_string(const char **pp, const char *end, const char **error)
{
    const char *p = *pp;
    if (*p != '"') {
        *error = "expected string";
        return NULL;
    }
    p++;

    const char *start = p;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end)
            p++;
        p++;
    }

    if (p >= end) {
        *error = "unterminated string";
        return NULL;
    }

    size_t len = (size_t)(p - start);
    json_value *val = test_alloc(sizeof(json_value));
    val->type = JSON_STRING;
    val->data.string.str = test_alloc(len + 1);
    memcpy(val->data.string.str, start, len);
    val->data.string.str[len] = '\0';
    val->data.string.len = len;

    *pp = p + 1;
    return val;
}

/* Parse number value */
static json_value *parse_number(const char **pp, const char *end, const char **error)
{
    (void)error;  /* Not used in number parsing */
    const char *p = *pp;
    boolean negative = false;
    s64 num = 0;

    if (*p == '-') {
        negative = true;
        p++;
    }

    while (p < end && *p >= '0' && *p <= '9') {
        num = num * 10 + (*p - '0');
        p++;
    }

    json_value *val = test_alloc(sizeof(json_value));
    val->type = JSON_NUMBER;
    val->data.num_val = negative ? -num : num;

    *pp = p;
    return val;
}

/* Forward declaration for recursive parsing */
static json_value *parse_value(const char **pp, const char *end, const char **error);

/* Parse array */
static json_value *parse_array(const char **pp, const char *end, const char **error)
{
    const char *p = *pp;
    if (*p != '[') {
        *error = "expected array";
        return NULL;
    }
    p++;

    json_value *arr = test_alloc(sizeof(json_value));
    arr->type = JSON_ARRAY;
    arr->data.array.items = NULL;
    arr->data.array.count = 0;

    p = skip_ws(p, end);
    if (p < end && *p == ']') {
        *pp = p + 1;
        return arr;
    }

    size_t capacity = 8;
    arr->data.array.items = test_alloc(capacity * sizeof(json_value *));

    while (p < end) {
        p = skip_ws(p, end);
        json_value *item = parse_value(&p, end, error);
        if (!item) {
            json_free(arr);
            return NULL;
        }

        if (arr->data.array.count >= capacity) {
            capacity *= 2;
            arr->data.array.items = realloc(arr->data.array.items,
                                            capacity * sizeof(json_value *));
        }
        arr->data.array.items[arr->data.array.count++] = item;

        p = skip_ws(p, end);
        if (p < end && *p == ']') {
            *pp = p + 1;
            return arr;
        }
        if (p >= end || *p != ',') {
            *error = "expected , or ]";
            json_free(arr);
            return NULL;
        }
        p++;
    }

    *error = "unterminated array";
    json_free(arr);
    return NULL;
}

/* Parse object */
static json_value *parse_object(const char **pp, const char *end, const char **error)
{
    const char *p = *pp;
    if (*p != '{') {
        *error = "expected object";
        return NULL;
    }
    p++;

    json_value *obj = test_alloc(sizeof(json_value));
    obj->type = JSON_OBJECT;
    obj->data.object.keys = NULL;
    obj->data.object.values = NULL;
    obj->data.object.count = 0;

    p = skip_ws(p, end);
    if (p < end && *p == '}') {
        *pp = p + 1;
        return obj;
    }

    size_t capacity = 8;
    obj->data.object.keys = test_alloc(capacity * sizeof(char *));
    obj->data.object.values = test_alloc(capacity * sizeof(json_value *));

    while (p < end) {
        p = skip_ws(p, end);

        /* Parse key */
        json_value *key_val = parse_string(&p, end, error);
        if (!key_val) {
            json_free(obj);
            return NULL;
        }
        char *key = key_val->data.string.str;
        test_free(key_val);

        p = skip_ws(p, end);
        if (p >= end || *p != ':') {
            *error = "expected :";
            test_free(key);
            json_free(obj);
            return NULL;
        }
        p++;

        p = skip_ws(p, end);
        json_value *value = parse_value(&p, end, error);
        if (!value) {
            test_free(key);
            json_free(obj);
            return NULL;
        }

        if (obj->data.object.count >= capacity) {
            capacity *= 2;
            obj->data.object.keys = realloc(obj->data.object.keys,
                                            capacity * sizeof(char *));
            obj->data.object.values = realloc(obj->data.object.values,
                                              capacity * sizeof(json_value *));
        }
        obj->data.object.keys[obj->data.object.count] = key;
        obj->data.object.values[obj->data.object.count] = value;
        obj->data.object.count++;

        p = skip_ws(p, end);
        if (p < end && *p == '}') {
            *pp = p + 1;
            return obj;
        }
        if (p >= end || *p != ',') {
            *error = "expected , or }";
            json_free(obj);
            return NULL;
        }
        p++;
    }

    *error = "unterminated object";
    json_free(obj);
    return NULL;
}

/* Parse any JSON value */
static json_value *parse_value(const char **pp, const char *end, const char **error)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end) {
        *error = "unexpected end of input";
        return NULL;
    }

    json_value *val;

    if (*p == '"') {
        val = parse_string(&p, end, error);
    } else if (*p == '[') {
        val = parse_array(&p, end, error);
    } else if (*p == '{') {
        val = parse_object(&p, end, error);
    } else if (*p == 't' && p + 4 <= end && memcmp(p, "true", 4) == 0) {
        val = test_alloc(sizeof(json_value));
        val->type = JSON_BOOL;
        val->data.bool_val = true;
        p += 4;
    } else if (*p == 'f' && p + 5 <= end && memcmp(p, "false", 5) == 0) {
        val = test_alloc(sizeof(json_value));
        val->type = JSON_BOOL;
        val->data.bool_val = false;
        p += 5;
    } else if (*p == 'n' && p + 4 <= end && memcmp(p, "null", 4) == 0) {
        val = test_alloc(sizeof(json_value));
        val->type = JSON_NULL;
        p += 4;
    } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
        val = parse_number(&p, end, error);
    } else {
        *error = "unexpected character";
        return NULL;
    }

    *pp = p;
    return val;
}

/* Parse JSON string */
static json_value *json_parse(const char *json, size_t len, const char **error)
{
    const char *p = json;
    const char *end = json + len;
    *error = NULL;

    json_value *val = parse_value(&p, end, error);
    if (!val)
        return NULL;

    p = skip_ws(p, end);
    if (p != end) {
        *error = "trailing content";
        json_free(val);
        return NULL;
    }

    return val;
}

/* Free JSON value */
static void json_free(json_value *val)
{
    if (!val)
        return;

    switch (val->type) {
    case JSON_STRING:
        test_free(val->data.string.str);
        break;
    case JSON_ARRAY:
        for (size_t i = 0; i < val->data.array.count; i++)
            json_free(val->data.array.items[i]);
        test_free(val->data.array.items);
        break;
    case JSON_OBJECT:
        for (size_t i = 0; i < val->data.object.count; i++) {
            test_free(val->data.object.keys[i]);
            json_free(val->data.object.values[i]);
        }
        test_free(val->data.object.keys);
        test_free(val->data.object.values);
        break;
    default:
        break;
    }
    test_free(val);
}

/* Get object member by key */
static json_value *json_get(json_value *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJECT)
        return NULL;

    for (size_t i = 0; i < obj->data.object.count; i++) {
        if (strcmp(obj->data.object.keys[i], key) == 0)
            return obj->data.object.values[i];
    }
    return NULL;
}

/* Get string value */
static const char *json_get_string(json_value *obj, const char *key)
{
    json_value *val = json_get(obj, key);
    if (!val || val->type != JSON_STRING)
        return NULL;
    return val->data.string.str;
}

/* Get array value */
static json_value *json_get_array(json_value *obj, const char *key)
{
    json_value *val = json_get(obj, key);
    if (!val || val->type != JSON_ARRAY)
        return NULL;
    return val;
}

/* ============================================================
 * POLICY STRUCTURE (for testing)
 * ============================================================ */

typedef struct ak_test_policy {
    char *version;

    /* FS rules */
    struct {
        char **read_patterns;
        size_t read_count;
        char **write_patterns;
        size_t write_count;
    } fs;

    /* Net rules */
    struct {
        char **dns_patterns;
        size_t dns_count;
        char **connect_patterns;
        size_t connect_count;
    } net;

    /* Tools */
    struct {
        char **allow_patterns;
        size_t allow_count;
    } tools;

    /* Inference */
    struct {
        char **models;
        size_t model_count;
        s64 max_tokens;
    } infer;

    /* Budgets */
    struct {
        s64 tool_calls;
    } budgets;
} ak_test_policy;

/* Parse string array from JSON */
static boolean parse_string_array(json_value *arr, char ***out, size_t *count)
{
    if (!arr || arr->type != JSON_ARRAY) {
        *out = NULL;
        *count = 0;
        return true;
    }

    *count = arr->data.array.count;
    *out = test_alloc(*count * sizeof(char *));

    for (size_t i = 0; i < *count; i++) {
        json_value *item = arr->data.array.items[i];
        if (item->type != JSON_STRING) {
            for (size_t j = 0; j < i; j++)
                test_free((*out)[j]);
            test_free(*out);
            *out = NULL;
            *count = 0;
            return false;
        }
        (*out)[i] = strdup(item->data.string.str);
    }

    return true;
}

/* Parse policy from JSON */
static ak_test_policy *policy_parse(const char *json, size_t len, const char **error)
{
    json_value *root = json_parse(json, len, error);
    if (!root)
        return NULL;

    ak_test_policy *policy = test_alloc(sizeof(ak_test_policy));
    memset(policy, 0, sizeof(ak_test_policy));

    /* Version */
    const char *version = json_get_string(root, "version");
    if (version)
        policy->version = strdup(version);

    /* FS rules */
    json_value *fs = json_get(root, "fs");
    if (fs) {
        parse_string_array(json_get_array(fs, "read"),
                          &policy->fs.read_patterns, &policy->fs.read_count);
        parse_string_array(json_get_array(fs, "write"),
                          &policy->fs.write_patterns, &policy->fs.write_count);
    }

    /* Net rules */
    json_value *net = json_get(root, "net");
    if (net) {
        parse_string_array(json_get_array(net, "dns"),
                          &policy->net.dns_patterns, &policy->net.dns_count);
        parse_string_array(json_get_array(net, "connect"),
                          &policy->net.connect_patterns, &policy->net.connect_count);
    }

    /* Tools */
    json_value *tools = json_get(root, "tools");
    if (tools) {
        parse_string_array(json_get_array(tools, "allow"),
                          &policy->tools.allow_patterns, &policy->tools.allow_count);
    }

    /* Inference */
    json_value *infer = json_get(root, "infer");
    if (infer) {
        parse_string_array(json_get_array(infer, "models"),
                          &policy->infer.models, &policy->infer.model_count);
        json_value *max_tokens = json_get(infer, "max_tokens");
        if (max_tokens && max_tokens->type == JSON_NUMBER)
            policy->infer.max_tokens = max_tokens->data.num_val;
    }

    /* Budgets */
    json_value *budgets = json_get(root, "budgets");
    if (budgets) {
        json_value *tool_calls = json_get(budgets, "tool_calls");
        if (tool_calls && tool_calls->type == JSON_NUMBER)
            policy->budgets.tool_calls = tool_calls->data.num_val;
    }

    json_free(root);
    return policy;
}

/* Free policy */
static void policy_free(ak_test_policy *policy)
{
    if (!policy)
        return;

    test_free(policy->version);

    for (size_t i = 0; i < policy->fs.read_count; i++)
        test_free(policy->fs.read_patterns[i]);
    test_free(policy->fs.read_patterns);

    for (size_t i = 0; i < policy->fs.write_count; i++)
        test_free(policy->fs.write_patterns[i]);
    test_free(policy->fs.write_patterns);

    for (size_t i = 0; i < policy->net.dns_count; i++)
        test_free(policy->net.dns_patterns[i]);
    test_free(policy->net.dns_patterns);

    for (size_t i = 0; i < policy->net.connect_count; i++)
        test_free(policy->net.connect_patterns[i]);
    test_free(policy->net.connect_patterns);

    for (size_t i = 0; i < policy->tools.allow_count; i++)
        test_free(policy->tools.allow_patterns[i]);
    test_free(policy->tools.allow_patterns);

    for (size_t i = 0; i < policy->infer.model_count; i++)
        test_free(policy->infer.models[i]);
    test_free(policy->infer.models);

    test_free(policy);
}

/* ============================================================
 * TEST CASES: JSON PARSING
 * ============================================================ */

boolean test_json_empty_object(void)
{
    const char *error;
    json_value *val = json_parse("{}", 2, &error);
    test_assert(val != NULL);
    test_assert(val->type == JSON_OBJECT);
    test_assert(val->data.object.count == 0);
    json_free(val);
    return true;
}

boolean test_json_simple_string(void)
{
    const char *error;
    const char *json = "{\"key\": \"value\"}";
    json_value *val = json_parse(json, strlen(json), &error);
    test_assert(val != NULL);
    test_assert(val->type == JSON_OBJECT);

    const char *str = json_get_string(val, "key");
    test_assert(str != NULL);
    test_assert(strcmp(str, "value") == 0);

    json_free(val);
    return true;
}

boolean test_json_nested_object(void)
{
    const char *error;
    const char *json = "{\"outer\": {\"inner\": \"value\"}}";
    json_value *val = json_parse(json, strlen(json), &error);
    test_assert(val != NULL);

    json_value *outer = json_get(val, "outer");
    test_assert(outer != NULL);
    test_assert(outer->type == JSON_OBJECT);

    const char *inner = json_get_string(outer, "inner");
    test_assert(inner != NULL);
    test_assert(strcmp(inner, "value") == 0);

    json_free(val);
    return true;
}

boolean test_json_array(void)
{
    const char *error;
    const char *json = "{\"arr\": [\"a\", \"b\", \"c\"]}";
    json_value *val = json_parse(json, strlen(json), &error);
    test_assert(val != NULL);

    json_value *arr = json_get_array(val, "arr");
    test_assert(arr != NULL);
    test_assert(arr->data.array.count == 3);

    json_free(val);
    return true;
}

boolean test_json_number(void)
{
    const char *error;
    const char *json = "{\"num\": 12345}";
    json_value *val = json_parse(json, strlen(json), &error);
    test_assert(val != NULL);

    json_value *num = json_get(val, "num");
    test_assert(num != NULL);
    test_assert(num->type == JSON_NUMBER);
    test_assert(num->data.num_val == 12345);

    json_free(val);
    return true;
}

boolean test_json_boolean(void)
{
    const char *error;
    const char *json = "{\"flag\": true}";
    json_value *val = json_parse(json, strlen(json), &error);
    test_assert(val != NULL);

    json_value *flag = json_get(val, "flag");
    test_assert(flag != NULL);
    test_assert(flag->type == JSON_BOOL);
    test_assert(flag->data.bool_val == true);

    json_free(val);
    return true;
}

/* ============================================================
 * TEST CASES: POLICY PARSING
 * ============================================================ */

boolean test_policy_minimal(void)
{
    const char *error;
    const char *json = "{\"version\": \"1.0\"}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(strcmp(policy->version, "1.0") == 0);
    policy_free(policy);
    return true;
}

boolean test_policy_fs_rules(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"fs\": {"
        "    \"read\": [\"/app/**\", \"/lib/**\"],"
        "    \"write\": [\"/tmp/**\"]"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->fs.read_count == 2);
    test_assert(policy->fs.write_count == 1);
    test_assert(strcmp(policy->fs.read_patterns[0], "/app/**") == 0);
    test_assert(strcmp(policy->fs.read_patterns[1], "/lib/**") == 0);
    test_assert(strcmp(policy->fs.write_patterns[0], "/tmp/**") == 0);
    policy_free(policy);
    return true;
}

boolean test_policy_net_rules(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"net\": {"
        "    \"dns\": [\"example.com\", \"*.api.example.com\"],"
        "    \"connect\": [\"dns:example.com:443\"]"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->net.dns_count == 2);
    test_assert(policy->net.connect_count == 1);
    test_assert(strcmp(policy->net.dns_patterns[0], "example.com") == 0);
    policy_free(policy);
    return true;
}

boolean test_policy_tools(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"tools\": {"
        "    \"allow\": [\"read_file\", \"write_file\", \"http_*\"]"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->tools.allow_count == 3);
    test_assert(strcmp(policy->tools.allow_patterns[0], "read_file") == 0);
    test_assert(strcmp(policy->tools.allow_patterns[2], "http_*") == 0);
    policy_free(policy);
    return true;
}

boolean test_policy_inference(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"infer\": {"
        "    \"models\": [\"gpt-4\", \"claude-3\"],"
        "    \"max_tokens\": 4096"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->infer.model_count == 2);
    test_assert(policy->infer.max_tokens == 4096);
    test_assert(strcmp(policy->infer.models[0], "gpt-4") == 0);
    policy_free(policy);
    return true;
}

boolean test_policy_budgets(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"budgets\": {"
        "    \"tool_calls\": 100"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->budgets.tool_calls == 100);
    policy_free(policy);
    return true;
}

boolean test_policy_full(void)
{
    const char *error;
    const char *json =
        "{"
        "  \"version\": \"1.0\","
        "  \"fs\": {"
        "    \"read\": [\"/app/**\"],"
        "    \"write\": [\"/tmp/**\"]"
        "  },"
        "  \"net\": {"
        "    \"dns\": [\"example.com\"],"
        "    \"connect\": [\"dns:example.com:443\"]"
        "  },"
        "  \"tools\": {"
        "    \"allow\": [\"test_tool\"]"
        "  },"
        "  \"infer\": {"
        "    \"models\": [\"test-model\"],"
        "    \"max_tokens\": 1000"
        "  },"
        "  \"budgets\": {"
        "    \"tool_calls\": 10"
        "  }"
        "}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(strcmp(policy->version, "1.0") == 0);
    test_assert(policy->fs.read_count == 1);
    test_assert(policy->fs.write_count == 1);
    test_assert(policy->net.dns_count == 1);
    test_assert(policy->net.connect_count == 1);
    test_assert(policy->tools.allow_count == 1);
    test_assert(policy->infer.model_count == 1);
    test_assert(policy->infer.max_tokens == 1000);
    test_assert(policy->budgets.tool_calls == 10);
    policy_free(policy);
    return true;
}

/* ============================================================
 * TEST CASES: MISSING POLICY BEHAVIOR
 * ============================================================ */

boolean test_policy_missing_version(void)
{
    const char *error;
    const char *json = "{\"fs\": {\"read\": [\"/app/**\"]}}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->version == NULL);  /* Missing version should be NULL */
    policy_free(policy);
    return true;
}

boolean test_policy_empty_arrays(void)
{
    const char *error;
    const char *json = "{\"fs\": {\"read\": [], \"write\": []}}";
    ak_test_policy *policy = policy_parse(json, strlen(json), &error);
    test_assert(policy != NULL);
    test_assert(policy->fs.read_count == 0);
    test_assert(policy->fs.write_count == 0);
    policy_free(policy);
    return true;
}

/* ============================================================
 * TEST CASES: INVALID JSON HANDLING
 * ============================================================ */

boolean test_invalid_json_syntax(void)
{
    const char *error;
    json_value *val;

    /* Missing closing brace */
    val = json_parse("{\"key\": \"value\"", 15, &error);
    test_assert(val == NULL);
    test_assert(error != NULL);

    /* Missing quotes */
    val = json_parse("{key: \"value\"}", 14, &error);
    test_assert(val == NULL);

    /* Trailing comma */
    val = json_parse("{\"key\": \"value\",}", 17, &error);
    test_assert(val == NULL);

    return true;
}

boolean test_invalid_json_empty(void)
{
    const char *error;
    json_value *val = json_parse("", 0, &error);
    test_assert(val == NULL);
    test_assert(error != NULL);
    return true;
}

/* ============================================================
 * TEST RUNNER
 * ============================================================ */

typedef boolean (*test_func)(void);

typedef struct {
    const char *name;
    test_func func;
} test_case;

test_case tests[] = {
    /* JSON parsing tests */
    {"json_empty_object", test_json_empty_object},
    {"json_simple_string", test_json_simple_string},
    {"json_nested_object", test_json_nested_object},
    {"json_array", test_json_array},
    {"json_number", test_json_number},
    {"json_boolean", test_json_boolean},

    /* Policy parsing tests */
    {"policy_minimal", test_policy_minimal},
    {"policy_fs_rules", test_policy_fs_rules},
    {"policy_net_rules", test_policy_net_rules},
    {"policy_tools", test_policy_tools},
    {"policy_inference", test_policy_inference},
    {"policy_budgets", test_policy_budgets},
    {"policy_full", test_policy_full},

    /* Missing policy behavior */
    {"policy_missing_version", test_policy_missing_version},
    {"policy_empty_arrays", test_policy_empty_arrays},

    /* Invalid JSON handling */
    {"invalid_json_syntax", test_invalid_json_syntax},
    {"invalid_json_empty", test_invalid_json_empty},

    {NULL, NULL}
};

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int passed = 0;
    int failed = 0;

    printf("=== AK Policy Parsing Tests ===\n\n");

    for (int i = 0; tests[i].name != NULL; i++) {
        printf("Running %s... ", tests[i].name);
        if (tests[i].func()) {
            printf("PASS\n");
            passed++;
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);

    return (failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
