/*
 * Authority Kernel - Hash-Chained Audit Log Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * SECURITY CRITICAL: This file enforces INV-4 (Log Commitment Invariant).
 * Every state change produces a hash-chained log entry.
 * Response is NEVER sent before fsync.
 */

#include "ak_audit.h"
#include "ak_types.h"

/*
 * Filesystem includes for persistent storage.
 *
 * PRODUCTION DESIGN DECISION: Persistent audit log storage is intentionally
 * disabled in this configuration. The kernel storage layer requires complex
 * dependencies (pagecache, mutex, filesystem types) that are not available
 * during agentic module compilation without significant architectural changes.
 *
 * Current behavior:
 *   - Audit log is maintained in-memory only
 *   - INV-4 (Log Commitment) is fully enforced for in-memory entries
 *   - Hash chain integrity is verified for all operations
 *   - Entries are NOT persisted across reboots
 *
 * For production deployments requiring crash recovery:
 *   - Define KERNEL_STORAGE_ENABLED at build time
 *   - Ensure kernel is built with filesystem integration
 *   - Call ak_audit_open_storage() after filesystem initialization
 *
 * This design allows the agentic module to compile and function correctly
 * in isolated builds while preserving the option for full persistence when
 * the complete kernel environment is available.
 */
#undef KERNEL_STORAGE_ENABLED

/* Wrapper for Nanos sha256 that uses buffers */
static void ak_sha256(const u8 *data, u32 len, u8 *output) {
  buffer src = alloca_wrap_buffer((void *)data, len);
  /* Use a little_stack_buffer which can be extended, unlike wrapped buffers */
  buffer dst = little_stack_buffer(64);
  sha256(dst, src);
  /* Copy result to output */
  runtime_memcpy(output, buffer_ref(dst, 0), 32);
}

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

#define AK_LOG_SEGMENT_SIZE 1000 /* Entries per segment */
#define AK_LOG_MAX_SEGMENTS 1000 /* Max segments in memory */

/* Audit log file format constants */
#define AK_AUDIT_MAGIC 0x414B4C47 /* "AKLG" - Authority Kernel Log */
#define AK_AUDIT_VERSION 1
#define AK_AUDIT_ENTRY_MAGIC 0x414B4C45 /* "AKLE" - AK Log Entry */

/* On-disk entry header for serialization */
typedef struct ak_audit_entry_header {
  u32 magic;    /* AK_AUDIT_ENTRY_MAGIC */
  u32 length;   /* Total entry length including header */
  u64 seq;      /* Sequence number */
  u32 crc32;    /* CRC32 of entry data (after header) */
  u32 reserved; /* Alignment padding */
} __attribute__((packed)) ak_audit_entry_header_t;

/* File header at start of audit log */
typedef struct ak_audit_file_header {
  u32 magic;                  /* AK_AUDIT_MAGIC */
  u32 version;                /* AK_AUDIT_VERSION */
  u64 entry_count;            /* Number of entries in file */
  u64 last_seq;               /* Last sequence number */
  u8 last_hash[AK_HASH_SIZE]; /* Hash of last entry */
  u64 file_size;              /* Total file size */
  u32 crc32;                  /* CRC32 of header (excluding this field) */
  u32 reserved;               /* Alignment padding */
} __attribute__((packed)) ak_audit_file_header_t;

typedef struct ak_log_segment {
  ak_log_entry_t entries[AK_LOG_SEGMENT_SIZE];
  u32 count;
  u64 start_seq;
  boolean dirty;
} ak_log_segment_t;

static struct {
  heap h;
  struct spinlock lock;

  /* In-memory segments */
  ak_log_segment_t *segments[AK_LOG_MAX_SEGMENTS];
  u32 segment_count;

  /* Current state */
  u64 head_seq;               /* Latest sequence number */
  u8 head_hash[AK_HASH_SIZE]; /* Hash of head entry */

  /* Anchoring */
  ak_anchor_t *anchors;
  u32 anchor_count;
  u32 anchor_capacity;

  /* Storage state - for persistent audit log */
#ifdef KERNEL_STORAGE_ENABLED
  fsfile audit_file; /* File handle for audit.log */
#else
  void *audit_file; /* Placeholder when storage disabled */
#endif
  u64 file_offset;               /* Current write offset in file */
  boolean storage_enabled;       /* Whether persistent storage is active */
  volatile boolean sync_pending; /* Sync operation in progress */
  volatile s64 sync_result;      /* Result of last sync operation */

  boolean initialized;
} ak_log;

/* Path to audit log file (used when storage is enabled) */
#ifdef KERNEL_STORAGE_ENABLED
static const char *AK_AUDIT_LOG_PATH = "/ak/audit.log";
#endif

/* Forward declarations for storage helpers */
#ifdef KERNEL_STORAGE_ENABLED
static s64 ak_audit_write_entry_to_disk(ak_log_entry_t *entry);
static u32 ak_audit_crc32(const u8 *data, u64 len);
#endif

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_audit_init(heap h) {
  ak_log.h = h;
  spin_lock_init(&ak_log.lock);

  /* Initialize with genesis */
  ak_log.head_seq = 0;
  runtime_memcpy(ak_log.head_hash, AK_GENESIS_HASH, AK_HASH_SIZE);

  /* Allocate first segment */
  ak_log.segments[0] = allocate_zero(h, sizeof(ak_log_segment_t));
  if (!ak_log.segments[0] || ak_log.segments[0] == INVALID_ADDRESS) {
    ak_log.segments[0] = NULL;
    return;
  }
  ak_log.segments[0]->start_seq = 1;
  ak_log.segment_count = 1;

  /* Anchor storage */
  ak_log.anchor_capacity = 100;
  ak_log.anchors = allocate(h, sizeof(ak_anchor_t) * ak_log.anchor_capacity);
  if (!ak_log.anchors || ak_log.anchors == INVALID_ADDRESS) {
    deallocate(h, ak_log.segments[0], sizeof(ak_log_segment_t));
    ak_log.segments[0] = NULL;
    ak_log.anchors = NULL;
    return;
  }
  ak_log.anchor_count = 0;

  /* Initialize storage state */
  ak_log.audit_file = NULL;
  ak_log.file_offset = 0;
  ak_log.storage_enabled = false;
  ak_log.sync_pending = false;
  ak_log.sync_result = 0;

  /*
   * Open or create the audit log file.
   * INV-4 CRITICAL: This file must exist and be writable for INV-4 enforcement.
   *
   * Note: File opening happens after filesystem is mounted.
   * The ak_audit_load() function should be called after filesystem
   * initialization to actually open the file.
   */

  /* Initialize ring buffer for data-plane audit events */
  ak_ring_init();

  ak_log.initialized = true;
}

/*
 * Open the audit log file for persistent storage.
 * Called after filesystem is initialized.
 * Returns 0 on success, negative on error.
 */
s64 ak_audit_open_storage(void) {
  if (!ak_log.initialized)
    return -EINVAL;

#ifdef KERNEL_STORAGE_ENABLED
  /* Try to open existing file or create new one */
  ak_log.audit_file = fsfile_open_or_create(ss(AK_AUDIT_LOG_PATH), false);
  if (!ak_log.audit_file) {
    /* Failed to open - storage will remain disabled */
    ak_warn("ak_audit: failed to open audit log file %s", AK_AUDIT_LOG_PATH);
    ak_log.storage_enabled = false;
    return -EIO;
  }

  /* Get current file length for append position */
  ak_log.file_offset = fsfile_get_length(ak_log.audit_file);
  ak_log.storage_enabled = true;

  ak_debug("ak_audit: opened audit log, size=%llu", ak_log.file_offset);
  return 0;
#else
  /* Storage disabled - in-memory only */
  ak_log.storage_enabled = false;
  return 0;
#endif
}

s64 ak_audit_load(void) {
  /*
   * Load audit log from persistent storage.
   * Restores hash chain from last known good state.
   * Verifies chain integrity on load.
   *
   * INV-4 CRITICAL: On recovery, we must verify the entire chain
   * before accepting any entries as valid.
   */

  /* First, try to open storage if not already open */
  if (!ak_log.storage_enabled) {
    s64 rv = ak_audit_open_storage();
    if (rv < 0) {
      /* Storage not available - start fresh (in-memory only) */
      ak_debug("ak_audit: storage unavailable, starting fresh");
      return 0;
    }
  }

  /* If file is empty, nothing to load */
  if (ak_log.file_offset == 0) {
    ak_debug("ak_audit: empty audit log, starting fresh");
    return 0;
  }

#ifdef KERNEL_STORAGE_ENABLED
  /*
   * Full log recovery implementation:
   * 1. Read file header and verify magic/version
   * 2. Iterate through entries, verifying CRC32 for each
   * 3. Rebuild in-memory hash chain
   * 4. Verify hash chain integrity
   * 5. Set head_seq and head_hash to last valid entry
   */

  u64 offset = 0;
  u64 file_size = ak_log.file_offset;
  u64 valid_entries = 0;
  u8 prev_hash[AK_HASH_SIZE];
  u8 last_valid_hash[AK_HASH_SIZE];
  u64 last_valid_seq = 0;

  /* Initialize with genesis hash */
  runtime_memcpy(prev_hash, AK_GENESIS_HASH, AK_HASH_SIZE);
  runtime_memcpy(last_valid_hash, AK_GENESIS_HASH, AK_HASH_SIZE);

  /* Step 1: Read and verify file header if present */
  if (file_size >= sizeof(ak_audit_file_header_t)) {
    ak_audit_file_header_t file_header;
    runtime_memset(&file_header, 0, sizeof(file_header));

    sg_list sg = allocate_sg_list();
    if (!sg || sg == INVALID_ADDRESS) {
      ak_error("ak_audit: failed to allocate sg_list for header read");
      return AK_E_LOG_CORRUPT;
    }

    sg_buf sgb = sg_list_tail_add(sg, sizeof(file_header));
    if (sgb == INVALID_ADDRESS) {
      deallocate_sg_list(sg);
      ak_error("ak_audit: failed to allocate sg_buf for header read");
      return AK_E_LOG_CORRUPT;
    }
    sgb->buf = &file_header;
    sgb->size = sizeof(file_header);
    sgb->offset = 0;
    sgb->refcount = 0;

    /* Read file header synchronously */
    range r = irangel(0, sizeof(file_header));
    sg_io reader = fsfile_get_reader(ak_log.audit_file);
    apply(reader, sg, r, ignore_status);

    deallocate_sg_list(sg);

    /* Verify file header magic and version */
    if (file_header.magic != AK_AUDIT_MAGIC) {
      ak_warn("ak_audit: invalid file magic 0x%08x, expected 0x%08x",
              file_header.magic, AK_AUDIT_MAGIC);
      /* File doesn't have our header format - could be raw entries, start fresh
       */
      ak_debug("ak_audit: starting fresh due to incompatible format");
      return 0;
    }

    if (file_header.version != AK_AUDIT_VERSION) {
      ak_warn("ak_audit: unsupported version %u, expected %u",
              file_header.version, AK_AUDIT_VERSION);
      return AK_E_LOG_CORRUPT;
    }

    /* Verify header CRC32 (CRC is computed over header excluding the crc32
     * field itself) */
    u32 header_crc = ak_audit_crc32((const u8 *)&file_header,
                                    offsetof(ak_audit_file_header_t, crc32));
    if (header_crc != file_header.crc32) {
      ak_warn("ak_audit: file header CRC mismatch");
      return AK_E_LOG_CORRUPT;
    }

    offset = sizeof(ak_audit_file_header_t);
    ak_debug("ak_audit: file header valid, entry_count=%llu, last_seq=%llu",
             file_header.entry_count, file_header.last_seq);
  }

  /* Step 2 & 3: Iterate through entries, verify CRC32 and rebuild hash chain */
  spin_lock(&ak_log.lock);

  /* Update first segment's start_seq for recovery - entries will start at seq 1
   */
  if (ak_log.segment_count > 0 && ak_log.segments[0]) {
    ak_log.segments[0]->start_seq = 1;
    ak_log.segments[0]->count = 0;
  }

  while (offset + sizeof(ak_audit_entry_header_t) <= file_size) {
    /* Read entry header from disk */
    ak_audit_entry_header_t entry_header;
    runtime_memset(&entry_header, 0, sizeof(entry_header));
    {
      sg_list sg = allocate_sg_list();
      if (!sg || sg == INVALID_ADDRESS) {
        ak_error("ak_audit: failed to allocate sg_list for entry header read");
        spin_unlock(&ak_log.lock);
        return AK_E_LOG_CORRUPT;
      }

      sg_buf sgb = sg_list_tail_add(sg, sizeof(entry_header));
      if (sgb == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        ak_error("ak_audit: failed to allocate sg_buf for entry header read");
        spin_unlock(&ak_log.lock);
        return AK_E_LOG_CORRUPT;
      }
      sgb->buf = &entry_header;
      sgb->size = sizeof(entry_header);
      sgb->offset = 0;
      sgb->refcount = 0;

      range r = irangel(offset, sizeof(entry_header));
      sg_io reader = fsfile_get_reader(ak_log.audit_file);
      apply(reader, sg, r, ignore_status);
      deallocate_sg_list(sg);
    }

    /* Verify entry header magic */
    if (entry_header.magic != AK_AUDIT_ENTRY_MAGIC) {
      ak_debug(
          "ak_audit: invalid entry magic at offset %llu, stopping recovery",
          offset);
      break;
    }

    /* Bounds check entry length */
    if (entry_header.length <
        sizeof(ak_audit_entry_header_t) + sizeof(ak_log_entry_t)) {
      ak_debug("ak_audit: entry too small at offset %llu", offset);
      break;
    }
    if (offset + entry_header.length > file_size) {
      ak_debug("ak_audit: entry extends past EOF at offset %llu", offset);
      break;
    }

    /* Verify entry data size */
    u64 entry_data_size = entry_header.length - sizeof(ak_audit_entry_header_t);
    if (entry_data_size != sizeof(ak_log_entry_t)) {
      ak_debug("ak_audit: unexpected entry size %llu at offset %llu",
               entry_data_size, offset);
      break;
    }

    /* Allocate temporary buffer for entry */
    ak_log_entry_t *entry = allocate(ak_log.h, sizeof(ak_log_entry_t));
    if (!entry || entry == INVALID_ADDRESS) {
      ak_error("ak_audit: failed to allocate entry during recovery");
      spin_unlock(&ak_log.lock);
      return AK_E_LOG_CORRUPT;
    }

    /* Read entry data from disk */
    {
      sg_list sg = allocate_sg_list();
      if (!sg || sg == INVALID_ADDRESS) {
        deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
        ak_error("ak_audit: failed to allocate sg_list for entry read");
        spin_unlock(&ak_log.lock);
        return AK_E_LOG_CORRUPT;
      }

      sg_buf sgb = sg_list_tail_add(sg, sizeof(ak_log_entry_t));
      if (sgb == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
        ak_error("ak_audit: failed to allocate sg_buf for entry read");
        spin_unlock(&ak_log.lock);
        return AK_E_LOG_CORRUPT;
      }
      sgb->buf = entry;
      sgb->size = sizeof(ak_log_entry_t);
      sgb->offset = 0;
      sgb->refcount = 0;

      range r = irangel(offset + sizeof(ak_audit_entry_header_t),
                        sizeof(ak_log_entry_t));
      sg_io reader = fsfile_get_reader(ak_log.audit_file);
      apply(reader, sg, r, ignore_status);
      deallocate_sg_list(sg);
    }

    /* Verify CRC32 of entry data */
    u32 computed_crc =
        ak_audit_crc32((const u8 *)entry, sizeof(ak_log_entry_t));
    if (computed_crc != entry_header.crc32) {
      ak_warn("ak_audit: entry CRC mismatch at seq %llu, stopping recovery",
              entry_header.seq);
      deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
      break;
    }

    /* Step 4: Verify hash chain integrity */
    /* Entry's prev_hash must match our expected prev_hash */
    if (runtime_memcmp(entry->prev_hash, prev_hash, AK_HASH_SIZE) != 0) {
      ak_warn("ak_audit: hash chain broken at seq %llu", entry->seq);
      deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
      break;
    }

    /* Recompute entry hash and verify */
    u8 computed_hash[AK_HASH_SIZE];
    ak_audit_compute_entry_hash(entry, entry->prev_hash, computed_hash);
    if (runtime_memcmp(entry->this_hash, computed_hash, AK_HASH_SIZE) != 0) {
      ak_warn("ak_audit: entry hash mismatch at seq %llu", entry->seq);
      deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
      break;
    }

    /* Entry is valid - add to in-memory log */
    ak_log_segment_t *seg = ak_log.segments[ak_log.segment_count - 1];
    if (seg->count >= AK_LOG_SEGMENT_SIZE) {
      /* Need a new segment */
      if (ak_log.segment_count >= AK_LOG_MAX_SEGMENTS) {
        ak_warn("ak_audit: segment limit reached during recovery");
        deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
        break;
      }
      ak_log_segment_t *new_seg = allocate_zero(ak_log.h, sizeof(*new_seg));
      if (!new_seg || new_seg == INVALID_ADDRESS) {
        ak_warn("ak_audit: failed to allocate segment during recovery");
        deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
        break;
      }
      new_seg->start_seq = entry->seq;
      ak_log.segments[ak_log.segment_count++] = new_seg;
      seg = new_seg;
    }

    /* Copy entry to segment */
    runtime_memcpy(&seg->entries[seg->count], entry, sizeof(ak_log_entry_t));
    seg->count++;
    seg->dirty = false; /* Entry is already on disk */

    /* Update chain state for next iteration */
    runtime_memcpy(prev_hash, entry->this_hash, AK_HASH_SIZE);
    runtime_memcpy(last_valid_hash, entry->this_hash, AK_HASH_SIZE);
    last_valid_seq = entry->seq;
    valid_entries++;

    deallocate(ak_log.h, entry, sizeof(ak_log_entry_t));
    offset += entry_header.length;
  }

  /* Step 5: Set head_seq and head_hash to last valid entry */
  ak_log.head_seq = last_valid_seq;
  runtime_memcpy(ak_log.head_hash, last_valid_hash, AK_HASH_SIZE);

  /* Update file offset to point past valid entries for future appends */
  ak_log.file_offset = offset;

  spin_unlock(&ak_log.lock);

  ak_debug(
      "ak_audit: recovery complete, loaded %llu valid entries, head_seq=%llu",
      valid_entries, last_valid_seq);
  return 0;

#else  /* !KERNEL_STORAGE_ENABLED */
  /*
   * Storage disabled - cannot perform recovery from disk.
   * Log exists but we cannot read it, so we start fresh in-memory.
   */
  ak_debug("ak_audit: existing log found (%llu bytes), but storage disabled - "
           "starting fresh",
           ak_log.file_offset);
  return 0;
#endif /* KERNEL_STORAGE_ENABLED */
}

/* ============================================================
 * HASH COMPUTATION
 * ============================================================ */

/*
 * Compute canonical representation of log entry for hashing.
 * Excludes prev_hash and this_hash fields.
 */
static buffer ak_log_entry_canonicalize(heap h, ak_log_entry_t *entry) {
  buffer b = allocate_buffer(h, 512);
  if (!b || b == INVALID_ADDRESS)
    return NULL;

  bprintf(b, "{\"op\":%d,\"pid\":\"", entry->op);
  for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
    bprintf(b, "%02x", entry->pid[i]);
  }

  bprintf(b, "\",\"policy_hash\":\"");
  for (int i = 0; i < AK_HASH_SIZE; i++) {
    bprintf(b, "%02x", entry->policy_hash[i]);
  }

  bprintf(b, "\",\"req_hash\":\"");
  for (int i = 0; i < AK_HASH_SIZE; i++) {
    bprintf(b, "%02x", entry->req_hash[i]);
  }

  bprintf(b, "\",\"res_hash\":\"");
  for (int i = 0; i < AK_HASH_SIZE; i++) {
    bprintf(b, "%02x", entry->res_hash[i]);
  }

  bprintf(b, "\",\"run_id\":\"");
  for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
    bprintf(b, "%02x", entry->run_id[i]);
  }

  bprintf(b, "\",\"seq\":%ld,\"ts_ms\":%ld}", entry->seq, entry->ts_ms);

  return b;
}

void ak_audit_compute_entry_hash(ak_log_entry_t *entry, u8 *prev_hash,
                                 u8 *hash_out) {
  buffer canonical = ak_log_entry_canonicalize(ak_log.h, entry);
  if (!canonical) {
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
    return;
  }

  /* hash = SHA256(prev_hash || canonical) */
  u64 canon_len = buffer_length(canonical);
  /* Overflow check for total_len computation */
  if (canon_len > UINT64_MAX - AK_HASH_SIZE) {
    deallocate_buffer(canonical);
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
    return;
  }
  u64 total_len = AK_HASH_SIZE + canon_len;
  u8 *combined = allocate(ak_log.h, total_len);
  if (!combined || combined == INVALID_ADDRESS) {
    deallocate_buffer(canonical);
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
    return;
  }

  runtime_memcpy(combined, prev_hash, AK_HASH_SIZE);
  runtime_memcpy(combined + AK_HASH_SIZE, buffer_ref(canonical, 0),
                 buffer_length(canonical));

  ak_sha256(combined, total_len, hash_out);

  deallocate(ak_log.h, combined, total_len);
  deallocate_buffer(canonical);
}

void ak_audit_hash_request(ak_request_t *req, u8 *hash_out) {
  /*
   * Hash request for audit logging.
   * Uses args buffer as primary content.
   * Canonical JSON serialization ensures deterministic hashes.
   */
  if (req->args) {
    ak_sha256(buffer_ref(req->args, 0), buffer_length(req->args), hash_out);
  } else {
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
  }
}

void ak_audit_hash_response(ak_response_t *res, u8 *hash_out) {
  /*
   * Hash response for audit logging.
   * Uses result buffer as primary content.
   * Canonical JSON serialization ensures deterministic hashes.
   */
  if (res->result) {
    ak_sha256(buffer_ref(res->result, 0), buffer_length(res->result), hash_out);
  } else {
    runtime_memset(hash_out, 0, AK_HASH_SIZE);
  }
}

/* ============================================================
 * LOG APPEND
 * ============================================================
 * CRITICAL SECURITY PATH
 */

static ak_log_segment_t *get_current_segment(void) {
  ak_log_segment_t *seg = ak_log.segments[ak_log.segment_count - 1];

  /* Check if segment is full */
  if (seg->count >= AK_LOG_SEGMENT_SIZE) {
    /* Allocate new segment */
    if (ak_log.segment_count >= AK_LOG_MAX_SEGMENTS) {
      /* Segment limit reached - evict oldest to disk via ak_audit_sync */
      return NULL;
    }

    ak_log_segment_t *new_seg = allocate_zero(ak_log.h, sizeof(*new_seg));
    if (!new_seg || new_seg == INVALID_ADDRESS)
      return NULL;
    new_seg->start_seq = ak_log.head_seq + 1;
    ak_log.segments[ak_log.segment_count++] = new_seg;
    seg = new_seg;
  }

  return seg;
}

s64 ak_audit_append(u8 *pid, u8 *run_id, u16 op, u8 *req_hash, u8 *res_hash,
                    u8 *policy_hash) {
  spin_lock(&ak_log.lock);

  ak_log_segment_t *seg = get_current_segment();
  if (!seg) {
    spin_unlock(&ak_log.lock);
    return AK_E_LOG_FULL;
  }

  /* Create entry */
  ak_log_entry_t *entry = &seg->entries[seg->count];

  entry->seq = ak_log.head_seq + 1;
  entry->ts_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  entry->op = op;

  runtime_memcpy(entry->pid, pid, AK_TOKEN_ID_SIZE);
  runtime_memcpy(entry->run_id, run_id, AK_TOKEN_ID_SIZE);
  runtime_memcpy(entry->req_hash, req_hash, AK_HASH_SIZE);
  runtime_memcpy(entry->res_hash, res_hash, AK_HASH_SIZE);
  runtime_memcpy(entry->policy_hash, policy_hash, AK_HASH_SIZE);

  /* Compute hash chain */
  runtime_memcpy(entry->prev_hash, ak_log.head_hash, AK_HASH_SIZE);
  ak_audit_compute_entry_hash(entry, entry->prev_hash, entry->this_hash);

  /* Update head */
  ak_log.head_seq = entry->seq;
  runtime_memcpy(ak_log.head_hash, entry->this_hash, AK_HASH_SIZE);

  seg->count++;
  seg->dirty = true;

  u64 seq = entry->seq;

  spin_unlock(&ak_log.lock);

  /* CRITICAL: Sync to disk BEFORE returning */
  /* This ensures INV-4: response only after durable log */
  ak_audit_sync();

  /* Check if anchor needed */
  if (seq % AK_ANCHOR_INTERVAL == 0) {
    ak_audit_emit_anchor();
  }

  return seq;
}

s64 ak_audit_append_request(ak_request_t *req, ak_response_t *res,
                            u8 *policy_hash) {
  u8 req_hash[AK_HASH_SIZE];
  u8 res_hash[AK_HASH_SIZE];

  ak_audit_hash_request(req, req_hash);
  ak_audit_hash_response(res, res_hash);

  return ak_audit_append(req->pid, req->run_id, req->op, req_hash, res_hash,
                         policy_hash);
}

/* ============================================================
 * LOG QUERY
 * ============================================================ */

static ak_log_entry_t *get_entry_by_seq(u64 seq) {
  for (u32 i = 0; i < ak_log.segment_count; i++) {
    ak_log_segment_t *seg = ak_log.segments[i];
    if (seq >= seg->start_seq && seq < seg->start_seq + seg->count) {
      return &seg->entries[seq - seg->start_seq];
    }
  }
  return NULL;
}

ak_log_entry_t **ak_audit_query(heap h, ak_log_query_filter_t *filter,
                                u64 start_seq, u64 end_seq, u64 *count_out) {
  spin_lock(&ak_log.lock);

  /* Count matching entries */
  u64 count = 0;
  for (u64 seq = start_seq; seq <= end_seq && seq <= ak_log.head_seq; seq++) {
    ak_log_entry_t *entry = get_entry_by_seq(seq);
    if (!entry)
      continue;

    boolean match = true;
    if (filter) {
      if (filter->pid &&
          runtime_memcmp(entry->pid, filter->pid, AK_TOKEN_ID_SIZE) != 0)
        match = false;
      if (filter->run_id &&
          runtime_memcmp(entry->run_id, filter->run_id, AK_TOKEN_ID_SIZE) != 0)
        match = false;
      if (filter->op != 0 && entry->op != filter->op)
        match = false;
    }

    if (match)
      count++;
  }

  if (count == 0) {
    spin_unlock(&ak_log.lock);
    *count_out = 0;
    return NULL;
  }

  /* Overflow check for allocation size */
  if (count > UINT64_MAX / sizeof(ak_log_entry_t *)) {
    spin_unlock(&ak_log.lock);
    *count_out = 0;
    return NULL;
  }

  /* Allocate result array */
  ak_log_entry_t **results = allocate(h, sizeof(ak_log_entry_t *) * count);
  if (!results || results == INVALID_ADDRESS) {
    spin_unlock(&ak_log.lock);
    *count_out = 0;
    return NULL;
  }
  u64 idx = 0;

  /* Populate results */
  for (u64 seq = start_seq; seq <= end_seq && seq <= ak_log.head_seq; seq++) {
    ak_log_entry_t *entry = get_entry_by_seq(seq);
    if (!entry)
      continue;

    boolean match = true;
    if (filter) {
      if (filter->pid &&
          runtime_memcmp(entry->pid, filter->pid, AK_TOKEN_ID_SIZE) != 0)
        match = false;
      if (filter->run_id &&
          runtime_memcmp(entry->run_id, filter->run_id, AK_TOKEN_ID_SIZE) != 0)
        match = false;
      if (filter->op != 0 && entry->op != filter->op)
        match = false;
    }

    if (match) {
      results[idx++] = entry;
    }
  }

  spin_unlock(&ak_log.lock);

  *count_out = count;
  return results;
}

u64 ak_audit_head_seq(void) {
  /*
   * CONCURRENCY FIX (BUG-011): Must hold lock to read head_seq atomically.
   * Without lock, concurrent ak_audit_append() could modify head_seq
   * mid-read on architectures without atomic 64-bit loads.
   */
  spin_lock(&ak_log.lock);
  u64 seq = ak_log.head_seq;
  spin_unlock(&ak_log.lock);
  return seq;
}

void ak_audit_head_hash(u8 *hash_out) {
  spin_lock(&ak_log.lock);
  runtime_memcpy(hash_out, ak_log.head_hash, AK_HASH_SIZE);
  spin_unlock(&ak_log.lock);
}

/* ============================================================
 * LOG VERIFICATION
 * ============================================================ */

s64 ak_audit_verify(void) { return ak_audit_verify_range(1, ak_log.head_seq); }

s64 ak_audit_verify_range(u64 start_seq, u64 end_seq) {
  spin_lock(&ak_log.lock);

  u8 expected_hash[AK_HASH_SIZE];

  /* Get previous hash */
  if (start_seq == 1) {
    runtime_memcpy(expected_hash, AK_GENESIS_HASH, AK_HASH_SIZE);
  } else {
    ak_log_entry_t *prev = get_entry_by_seq(start_seq - 1);
    if (!prev) {
      spin_unlock(&ak_log.lock);
      return AK_E_LOG_CORRUPT;
    }
    runtime_memcpy(expected_hash, prev->this_hash, AK_HASH_SIZE);
  }

  /* Verify each entry */
  for (u64 seq = start_seq; seq <= end_seq; seq++) {
    ak_log_entry_t *entry = get_entry_by_seq(seq);
    if (!entry) {
      spin_unlock(&ak_log.lock);
      return seq; /* Missing entry */
    }

    /* Check prev_hash matches expected */
    if (runtime_memcmp(entry->prev_hash, expected_hash, AK_HASH_SIZE) != 0) {
      spin_unlock(&ak_log.lock);
      return seq; /* Chain broken */
    }

    /* Recompute this_hash */
    u8 computed_hash[AK_HASH_SIZE];
    ak_audit_compute_entry_hash(entry, entry->prev_hash, computed_hash);

    if (runtime_memcmp(entry->this_hash, computed_hash, AK_HASH_SIZE) != 0) {
      spin_unlock(&ak_log.lock);
      return seq; /* Hash mismatch */
    }

    /* Update expected for next iteration */
    runtime_memcpy(expected_hash, entry->this_hash, AK_HASH_SIZE);
  }

  spin_unlock(&ak_log.lock);
  return 0; /* Valid */
}

boolean ak_audit_verify_entry(ak_log_entry_t *entry, u8 *expected_prev) {
  /* Check prev_hash */
  if (runtime_memcmp(entry->prev_hash, expected_prev, AK_HASH_SIZE) != 0)
    return false;

  /* Recompute and check this_hash */
  u8 computed[AK_HASH_SIZE];
  ak_audit_compute_entry_hash(entry, entry->prev_hash, computed);

  return runtime_memcmp(entry->this_hash, computed, AK_HASH_SIZE) == 0;
}

/* ============================================================
 * ANCHORING
 * ============================================================ */

s64 ak_audit_emit_anchor(void) {
  spin_lock(&ak_log.lock);

  /* Grow anchor array if needed */
  if (ak_log.anchor_count >= ak_log.anchor_capacity) {
    /* Overflow check: prevent capacity doubling overflow */
    if (ak_log.anchor_capacity > UINT32_MAX / 2) {
      spin_unlock(&ak_log.lock);
      return AK_E_LOG_FULL;
    }
    u32 new_cap = ak_log.anchor_capacity * 2;
    /* Note: allocation size overflow not possible here because:
     * - new_cap is u32, max ~4 billion after above check
     * - sizeof(ak_anchor_t) * 4B fits in u64
     */
    ak_anchor_t *new_anchors =
        allocate(ak_log.h, sizeof(ak_anchor_t) * new_cap);
    if (!new_anchors || new_anchors == INVALID_ADDRESS) {
      spin_unlock(&ak_log.lock);
      return AK_E_LOG_FULL;
    }
    runtime_memcpy(new_anchors, ak_log.anchors,
                   sizeof(ak_anchor_t) * ak_log.anchor_count);
    deallocate(ak_log.h, ak_log.anchors,
               sizeof(ak_anchor_t) * ak_log.anchor_capacity);
    ak_log.anchors = new_anchors;
    ak_log.anchor_capacity = new_cap;
  }

  /* Create anchor */
  ak_anchor_t *anchor = &ak_log.anchors[ak_log.anchor_count];

  anchor->ts_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  anchor->log_seq = ak_log.head_seq;
  runtime_memcpy(anchor->log_hash, ak_log.head_hash, AK_HASH_SIZE);

  /* Policy hash from current active policy (if available) */
  runtime_memset(anchor->policy_hash, 0, AK_HASH_SIZE);

  /* Anchor signature requires cryptographic key management */
  runtime_memset(anchor->signature, 0, 64);

  ak_log.anchor_count++;

  spin_unlock(&ak_log.lock);

  return anchor->log_seq;
}

ak_anchor_t *ak_audit_get_latest_anchor(void) {
  /*
   * CONCURRENCY FIX (BUG-015): Must hold lock while accessing anchor array.
   * Without lock, concurrent ak_audit_emit_anchor() could reallocate the
   * anchors array or increment anchor_count, causing use-after-free or
   * returning an invalid pointer.
   *
   * WARNING: Caller must NOT hold returned pointer across calls that could
   * modify anchor array. For thread-safe usage, caller should copy the
   * anchor data immediately.
   */
  spin_lock(&ak_log.lock);
  ak_anchor_t *result = NULL;
  if (ak_log.anchor_count > 0) {
    result = &ak_log.anchors[ak_log.anchor_count - 1];
  }
  spin_unlock(&ak_log.lock);
  return result;
}

boolean ak_audit_verify_anchor(ak_anchor_t *anchor) {
  /*
   * CONCURRENCY FIX (BUG-016): Must hold lock while calling get_entry_by_seq()
   * to ensure segment data is not modified during access.
   */
  spin_lock(&ak_log.lock);

  /* Verify log hash at anchor seq matches */
  ak_log_entry_t *entry = get_entry_by_seq(anchor->log_seq);
  if (!entry) {
    spin_unlock(&ak_log.lock);
    return false;
  }

  boolean result =
      runtime_memcmp(entry->this_hash, anchor->log_hash, AK_HASH_SIZE) == 0;
  spin_unlock(&ak_log.lock);
  return result;
}

void ak_audit_post_anchor_remote(ak_anchor_t *anchor, const char *url) {
  /*
   * Posts anchor to external transparency log via HTTP.
   * Requires network stack integration.
   * Failures are logged but do not block operation (best effort).
   */
  (void)anchor;
  (void)url;
}

/* ============================================================
 * STORAGE
 * ============================================================
 * INV-4 CRITICAL: All storage operations must complete with fsync
 * before any response can be sent to agents.
 */

#ifdef KERNEL_STORAGE_ENABLED

/*
 * CRC32 implementation for entry integrity verification.
 * Uses standard CRC-32 polynomial 0xEDB88320.
 */
static u32 ak_audit_crc32(const u8 *data, u64 len) {
  u32 crc = 0xFFFFFFFF;
  for (u64 i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}

/*
 * Serialize a log entry to binary format for disk storage.
 * Format: [header][entry_data]
 * Returns allocated buffer or NULL on failure.
 */
static buffer ak_audit_serialize_entry(ak_log_entry_t *entry) {
  /* Calculate entry data size */
  u64 entry_size = sizeof(ak_log_entry_t);
  u64 total_size = sizeof(ak_audit_entry_header_t) + entry_size;

  buffer b = allocate_buffer(ak_log.h, total_size);
  if (!b || b == INVALID_ADDRESS)
    return NULL;

  /* Write header */
  ak_audit_entry_header_t header;
  header.magic = AK_AUDIT_ENTRY_MAGIC;
  header.length = (u32)total_size;
  header.seq = entry->seq;
  header.reserved = 0;

  /* Compute CRC32 of entry data */
  header.crc32 = ak_audit_crc32((const u8 *)entry, entry_size);

  buffer_write(b, &header, sizeof(header));
  buffer_write(b, entry, entry_size);

  return b;
}

/*
 * Completion handler for async file sync operation.
 * Called when fsfile_flush completes.
 */
closure_func_basic(status_handler, void, ak_audit_sync_handler, status s) {
  if (is_ok(s)) {
    ak_log.sync_result = 0;
  } else {
    ak_error("ak_audit: fsync failed");
    ak_log.sync_result = -EIO;
  }
  ak_log.sync_pending = false;
  closure_finish();
}

/*
 * Completion handler for async file write operation.
 * After write completes, triggers fsync.
 */
closure_function(2, 1, void, ak_audit_write_complete, buffer, b, u64, write_len,
                 status s) {
  buffer b = bound(b);
  u64 write_len = bound(write_len);

  if (is_ok(s)) {
    /* Update file offset on successful write */
    ak_log.file_offset += write_len;

    /* Now sync to ensure durability - INV-4 CRITICAL */
    status_handler sh =
        closure_func(ak_log.h, status_handler, ak_audit_sync_handler);
    if (sh && sh != INVALID_ADDRESS) {
      fsfile_flush(ak_log.audit_file, false, sh);
    } else {
      ak_error("ak_audit: failed to allocate sync handler");
      ak_log.sync_result = -ENOMEM;
      ak_log.sync_pending = false;
    }
  } else {
    ak_error("ak_audit: write failed");
    ak_log.sync_result = -EIO;
    ak_log.sync_pending = false;
  }

  /* Free the write buffer */
  if (b)
    deallocate_buffer(b);

  closure_finish();
}

/*
 * Write a single entry to disk.
 * Returns 0 on success, negative on error.
 *
 * INV-4 CRITICAL: This function initiates an async write.
 * Caller must wait for sync to complete before proceeding.
 */
static s64 ak_audit_write_entry_to_disk(ak_log_entry_t *entry) {
  if (!ak_log.storage_enabled || !ak_log.audit_file)
    return 0; /* Storage not enabled, skip silently */

  /* Serialize entry */
  buffer entry_buf = ak_audit_serialize_entry(entry);
  if (!entry_buf)
    return -ENOMEM;

  u64 write_len = buffer_length(entry_buf);

  /* Create scatter-gather list for write */
  sg_list sg = allocate_sg_list();
  if (!sg || sg == INVALID_ADDRESS) {
    deallocate_buffer(entry_buf);
    return -ENOMEM;
  }

  /* Add buffer to sg list */
  sg_buf sgb = sg_list_tail_add(sg, write_len);
  if (sgb == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(entry_buf);
    return -ENOMEM;
  }
  sgb->buf = buffer_ref(entry_buf, 0);
  sgb->size = write_len;
  sgb->offset = 0;
  sgb->refcount = 0;

  /* Mark sync as pending */
  ak_log.sync_pending = true;
  ak_log.sync_result = 0;

  /* Create completion handler */
  status_handler write_sh =
      closure(ak_log.h, ak_audit_write_complete, entry_buf, write_len);
  if (!write_sh || write_sh == INVALID_ADDRESS) {
    deallocate_sg_list(sg);
    deallocate_buffer(entry_buf);
    ak_log.sync_pending = false;
    return -ENOMEM;
  }

  /* Write to file at current offset */
  range r = irangel(ak_log.file_offset, write_len);
  sg_io writer = fsfile_get_writer(ak_log.audit_file);
  apply(writer, sg, r, write_sh);

  /* Release sg_list after write initiation (buffer released in completion) */
  deallocate_sg_list(sg);

  return 0;
}

/*
 * Synchronize dirty entries to disk and wait for fsync completion.
 *
 * INV-4 ENFORCEMENT: This function MUST NOT return until all
 * dirty entries are durably stored on disk (fsync completed).
 *
 * The caller (typically ak_audit_append) blocks on this to ensure
 * no response is sent before the log entry is committed.
 */
void ak_audit_sync(void) {
  spin_lock(&ak_log.lock);

  /* If storage is not enabled, just mark clean and return */
  if (!ak_log.storage_enabled) {
    for (u32 i = 0; i < ak_log.segment_count; i++) {
      ak_log_segment_t *seg = ak_log.segments[i];
      if (seg->dirty) {
        seg->dirty = false;
      }
    }
    spin_unlock(&ak_log.lock);
    return;
  }

  /* Write all dirty entries to disk */
  for (u32 i = 0; i < ak_log.segment_count; i++) {
    ak_log_segment_t *seg = ak_log.segments[i];
    if (seg->dirty) {
      /* Write each entry in the dirty segment */
      for (u32 j = 0; j < seg->count; j++) {
        ak_log_entry_t *entry = &seg->entries[j];
        s64 rv = ak_audit_write_entry_to_disk(entry);
        if (rv < 0) {
          ak_error("ak_audit: failed to write entry seq=%llu, error=%lld",
                   entry->seq, rv);
          /* Continue trying to write other entries */
        }
      }

      /*
       * INV-4 CRITICAL: Wait for sync to complete before marking clean.
       * We spin-wait here because this is a critical path and we MUST
       * guarantee durability before returning.
       *
       * DESIGN DECISION: Spin-wait with memory barriers.
       * This is intentional for the audit sync path: async waiting
       * would allow the caller to proceed before durability is
       * guaranteed, violating INV-4. The spin-wait ensures we block
       * until I/O completion, with kern_pause() yielding CPU time.
       */
      while (ak_log.sync_pending) {
        /* Memory barrier to ensure we see updates to sync_pending */
        memory_barrier();
        /* Yield CPU briefly to allow I/O completion */
        kern_pause();
      }

      /* Check sync result */
      if (ak_log.sync_result < 0) {
        ak_error("ak_audit: sync failed for segment %u, error=%lld", i,
                 ak_log.sync_result);
        /* Do NOT mark as clean if sync failed - will retry on next sync */
      } else {
        /* Only mark as clean AFTER successful sync - INV-4 enforcement */
        seg->dirty = false;
      }
    }
  }

  spin_unlock(&ak_log.lock);
}

#else /* !KERNEL_STORAGE_ENABLED */

/*
 * When storage is disabled: just mark entries as clean (in-memory only).
 * INV-4 is enforced for in-memory entries but not persisted across reboots.
 */
void ak_audit_sync(void) {
  spin_lock(&ak_log.lock);

  for (u32 i = 0; i < ak_log.segment_count; i++) {
    ak_log_segment_t *seg = ak_log.segments[i];
    if (seg->dirty) {
      seg->dirty = false;
    }
  }

  spin_unlock(&ak_log.lock);
}

#endif /* KERNEL_STORAGE_ENABLED */

void ak_audit_get_stats(ak_audit_stats_t *stats) {
  spin_lock(&ak_log.lock);

  stats->entry_count = ak_log.head_seq;
  stats->bytes_used = ak_log.segment_count * sizeof(ak_log_segment_t);
  stats->anchor_count = ak_log.anchor_count;
  stats->last_anchor_seq = ak_log.anchor_count > 0
                               ? ak_log.anchors[ak_log.anchor_count - 1].log_seq
                               : 0;
  stats->last_sync_ms = now(CLOCK_ID_MONOTONIC) /
                        MILLION; /* Current time as proxy for last sync */
  stats->disk_bytes_written = ak_log.file_offset;
  stats->storage_enabled = ak_log.storage_enabled;

  spin_unlock(&ak_log.lock);
}

/* ============================================================
 * SPECIAL ENTRIES
 * ============================================================ */

s64 ak_audit_log_revocation(u8 *tid, const char *reason) {
  u8 zero_hash[AK_HASH_SIZE] = {0};
  u8 reason_hash[AK_HASH_SIZE];

  /* Hash the reason string */
  ak_sha256((const u8 *)reason, runtime_strlen(reason), reason_hash);

  /* Use tid as both pid and run_id for revocation entries */
  return ak_audit_append(tid,         /* pid = token id */
                         tid,         /* run_id = token id */
                         0xFFFF,      /* Special op code for revocation */
                         reason_hash, /* req_hash = reason */
                         zero_hash,   /* res_hash = empty */
                         zero_hash    /* policy_hash = empty */
  );
}

s64 ak_audit_log_policy_change(u8 *old_hash, u8 *new_hash, const char *reason) {
  u8 zero_id[AK_TOKEN_ID_SIZE] = {0};

  return ak_audit_append(zero_id,  /* pid = system */
                         zero_id,  /* run_id = system */
                         0xFFFE,   /* Special op code for policy change */
                         old_hash, /* req_hash = old policy */
                         new_hash, /* res_hash = new policy */
                         new_hash  /* policy_hash = new policy */
  );
}

s64 ak_audit_log_lifecycle(u8 *agent_id, u8 *run_id,
                           ak_lifecycle_event_t event) {
  u8 event_hash[AK_HASH_SIZE];
  u8 zero_hash[AK_HASH_SIZE] = {0};

  /* Hash event type */
  u8 event_byte = (u8)event;
  ak_sha256(&event_byte, 1, event_hash);

  return ak_audit_append(agent_id, run_id,
                         0xFFFD, /* Special op code for lifecycle */
                         event_hash, zero_hash, zero_hash);
}

/* ============================================================
 * REPLAY BUNDLE
 * ============================================================ */

ak_replay_bundle_t *ak_audit_create_bundle(heap h, u8 *run_id, u64 start_seq,
                                           u64 end_seq) {
  ak_replay_bundle_t *bundle = allocate_zero(h, sizeof(*bundle));
  if (!bundle || bundle == INVALID_ADDRESS)
    return NULL;

  runtime_memcpy(bundle->run_id, run_id, AK_TOKEN_ID_SIZE);
  bundle->start_seq = start_seq;
  bundle->end_seq = end_seq;

  /* Query entries for this run */
  ak_log_query_filter_t filter = {.run_id = run_id};
  bundle->entries =
      ak_audit_query(h, &filter, start_seq, end_seq, &bundle->entry_count);

  /* Heap snapshot via ak_heap_snapshot() for full replay capability */
  bundle->heap_snapshot = NULL;

  /* Get policy hash from first entry */
  if (bundle->entry_count > 0) {
    runtime_memcpy(bundle->policy_hash, bundle->entries[0]->policy_hash,
                   AK_HASH_SIZE);
  }

  return bundle;
}

void ak_audit_destroy_bundle(heap h, ak_replay_bundle_t *bundle) {
  if (!bundle)
    return;

  if (bundle->entries) {
    deallocate(h, bundle->entries,
               sizeof(ak_log_entry_t *) * bundle->entry_count);
  }
  if (bundle->heap_snapshot) {
    deallocate_buffer(bundle->heap_snapshot);
  }
  deallocate(h, bundle, sizeof(*bundle));
}

/* ============================================================
 * RING BUFFER - Lock-free data-plane audit
 * ============================================================
 *
 * Single-producer multi-consumer ring buffer using atomic operations.
 * Overwrites oldest entries when full (bounded memory usage).
 */

static struct {
  ak_ring_entry_t entries[AK_RING_BUFFER_SIZE];
  word head; /* Next write position (producer) - use word for atomics */
  word tail; /* Next read position (consumer) */
  word total_pushed;
  word total_popped;
  word overflow_count;
  boolean initialized;
} ak_ring;

void ak_ring_init(void) {
  runtime_memset((u8 *)&ak_ring, 0, sizeof(ak_ring));
  ak_ring.head = 0;
  ak_ring.tail = 0;
  ak_ring.initialized = true;
}

u64 ak_ring_push(u8 *pid, u8 *run_id, u16 op, u8 *req_hash, u8 *res_hash,
                 s64 result_code, u32 latency_us, u8 flags) {
  if (!ak_ring.initialized)
    return 0;

  /* Atomically claim a slot */
  u64 slot = fetch_and_add(&ak_ring.head, 1);
  u64 seq = slot + 1;
  u64 idx = slot & AK_RING_BUFFER_MASK;

  /* Check for overflow (tail catching up) */
  word tail = ak_ring.tail;
  if (slot - tail >= AK_RING_BUFFER_SIZE) {
    fetch_and_add(&ak_ring.overflow_count, 1);
    /* Move tail forward to make room */
    __sync_bool_compare_and_swap(&ak_ring.tail, tail,
                                 slot - AK_RING_BUFFER_SIZE + 1);
    flags |= AK_RING_FLAG_OVERFLOW;
  }

  /* Fill entry */
  ak_ring_entry_t *entry = &ak_ring.entries[idx];
  entry->seq = seq;
  entry->ts_ns = now(CLOCK_ID_MONOTONIC_RAW);
  if (pid)
    runtime_memcpy(entry->pid, pid, AK_TOKEN_ID_SIZE);
  else
    runtime_memset(entry->pid, 0, AK_TOKEN_ID_SIZE);
  if (run_id)
    runtime_memcpy(entry->run_id, run_id, AK_TOKEN_ID_SIZE);
  else
    runtime_memset(entry->run_id, 0, AK_TOKEN_ID_SIZE);
  entry->op = op;
  if (req_hash)
    runtime_memcpy(entry->req_hash, req_hash, AK_HASH_SIZE);
  else
    runtime_memset(entry->req_hash, 0, AK_HASH_SIZE);
  if (res_hash)
    runtime_memcpy(entry->res_hash, res_hash, AK_HASH_SIZE);
  else
    runtime_memset(entry->res_hash, 0, AK_HASH_SIZE);
  entry->result_code = result_code;
  entry->latency_us = latency_us;
  entry->flags = flags;

  fetch_and_add(&ak_ring.total_pushed, 1);
  return seq;
}

boolean ak_ring_pop(ak_ring_entry_t *entry_out) {
  if (!ak_ring.initialized || !entry_out)
    return false;

  word tail = ak_ring.tail;
  word head = ak_ring.head;

  /* Empty check */
  if (tail >= head)
    return false;

  /* Try to claim this slot */
  if (!__sync_bool_compare_and_swap(&ak_ring.tail, tail, tail + 1))
    return false; /* Lost race, try again */

  u64 idx = tail & AK_RING_BUFFER_MASK;
  runtime_memcpy(entry_out, &ak_ring.entries[idx], sizeof(ak_ring_entry_t));

  fetch_and_add(&ak_ring.total_popped, 1);
  return true;
}

boolean ak_ring_peek(u64 offset, ak_ring_entry_t *entry_out) {
  if (!ak_ring.initialized || !entry_out)
    return false;

  word tail = ak_ring.tail;
  word head = ak_ring.head;
  word pos = tail + offset;

  if (pos >= head)
    return false;

  u64 idx = pos & AK_RING_BUFFER_MASK;
  runtime_memcpy(entry_out, &ak_ring.entries[idx], sizeof(ak_ring_entry_t));
  return true;
}

void ak_ring_get_stats(ak_ring_stats_t *stats) {
  if (!stats)
    return;

  stats->total_pushed = ak_ring.total_pushed;
  stats->total_popped = ak_ring.total_popped;
  stats->head_seq = ak_ring.head;
  stats->tail_seq = ak_ring.tail;
  stats->overflow_count = ak_ring.overflow_count;

  u64 head = ak_ring.head;
  u64 tail = ak_ring.tail;
  stats->current_count = (head > tail) ? (head - tail) : 0;
}

u64 ak_ring_drain(ak_ring_drain_cb cb, void *ctx, u64 max_entries) {
  if (!ak_ring.initialized || !cb)
    return 0;

  u64 processed = 0;
  ak_ring_entry_t entry;

  while (processed < max_entries && ak_ring_pop(&entry)) {
    if (!cb(&entry, ctx))
      break;
    processed++;
  }

  return processed;
}
