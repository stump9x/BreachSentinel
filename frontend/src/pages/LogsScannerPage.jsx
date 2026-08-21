import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import BookmarkAddOutlinedIcon from "@mui/icons-material/BookmarkAddOutlined";
import CloseIcon from "@mui/icons-material/Close";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import VisibilityOffOutlinedIcon from "@mui/icons-material/VisibilityOffOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import { api, buildQuery } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";

const POLL_MS = 1200;
const ACTIVE = new Set(["queued", "running"]);
const MAX_FILES_PER_UPLOAD = 3;
const UPLOAD_CONCURRENCY = MAX_FILES_PER_UPLOAD;
const UPLOAD_RETRIES = 2;
const UPLOAD_CHUNK_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_UPLOAD_BYTES = 1536 * 1024 * 1024;

function formatBytes(n) {
  const value = Number(n) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toISOString().slice(0, 10);
  } catch {
    return "—";
  }
}

function formatDateTime(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return "—";
  }
}

function fileIdentity(file) {
  return `${file.name}\u0000${file.size}\u0000${file.lastModified}`;
}

function fileKey(file, index) {
  return `${index}-${fileIdentity(file)}`;
}

function createUploadId() {
  const browserCrypto = globalThis.crypto;
  if (typeof browserCrypto?.randomUUID === "function") {
    return browserCrypto.randomUUID();
  }
  if (typeof browserCrypto?.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    browserCrypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return [...bytes]
      .map((byte, index) => {
        const value = byte.toString(16).padStart(2, "0");
        return [4, 6, 8, 10].includes(index) ? `-${value}` : value;
      })
      .join("");
  }
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (char) => {
    const random = Math.random() * 16 | 0;
    const value = char === "x" ? random : (random & 0x3) | 0x8;
    return value.toString(16);
  });
}

function isRetryableUploadError(error) {
  const status = Number(error?.status) || 0;
  return status === 0 || status === 408 || status === 429 || status >= 500;
}

function waitForRetry(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Upload aborted", "AbortError"));
      return;
    }
    let timer;
    let offlineTimer;
    const onOnline = () => {
      cleanup();
      resolve();
    };
    const onAbort = () => {
      cleanup();
      reject(new DOMException("Upload aborted", "AbortError"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(offlineTimer);
      if (typeof window !== "undefined") {
        window.removeEventListener("online", onOnline);
      }
      signal?.removeEventListener("abort", onAbort);
    };
    timer = setTimeout(() => {
      if (
        typeof window !== "undefined" &&
        typeof navigator !== "undefined" &&
        navigator.onLine === false
      ) {
        window.addEventListener("online", onOnline, { once: true });
        // Do not block forever if the browser's online state is stale.
        offlineTimer = setTimeout(onOnline, 30000);
      } else {
        onOnline();
      }
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export default function LogsScannerPage() {
  const { isStaff } = useAuth();
  const fileInputRef = useRef(null);
  const [uploads, setUploads] = useState([]);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [keyword, setKeyword] = useState("");
  const [busyUpload, setBusyUpload] = useState(false);
  const [busyScan, setBusyScan] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [maxUploadBytes, setMaxUploadBytes] = useState(DEFAULT_MAX_UPLOAD_BYTES);
  const [uploadProgress, setUploadProgress] = useState({ files: [] });
  const [scan, setScan] = useState(null);
  const [hits, setHits] = useState([]);
  const [kept, setKept] = useState([]);
  const [pendingFiles, setPendingFiles] = useState([]);
  const uploadControllerRef = useRef(null);
  const [labDomain, setLabDomain] = useState("");
  const [labTargetUrl, setLabTargetUrl] = useState("");
  const [labJob, setLabJob] = useState(null);
  const [labBusy, setLabBusy] = useState(false);
  const [labAllowlist, setLabAllowlist] = useState([]);
  const [allowlistBusy, setAllowlistBusy] = useState(false);
  const [labHistory, setLabHistory] = useState([]);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [showHiddenHistory, setShowHiddenHistory] = useState(false);

  const loadUploads = useCallback(async () => {
    const data = await api.get(
      `/api/v1/logs/uploads/${buildQuery({
        page_size: 100,
        ordering: "-created_at",
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
      })}`
    );
    const rows = data.results || data || [];
    setUploads(rows);
    setSelectedIds((current) => {
      const valid = new Set(rows.map((row) => row.id));
      return new Set([...current].filter((id) => valid.has(id)));
    });
  }, [dateFrom, dateTo]);

  const loadKept = useCallback(async () => {
    const data = await api.get(
      `/api/v1/logs/hits/kept/${buildQuery({ page_size: 200 })}`
    );
    setKept(data.results || data || []);
  }, []);

  const loadLimits = useCallback(async () => {
    const data = await api.get("/api/v1/logs/limits/");
    if (Number(data?.max_upload_bytes) > 0) {
      setMaxUploadBytes(Number(data.max_upload_bytes));
    }
  }, []);

  const loadLabAllowlist = useCallback(async () => {
    const data = await api.get("/api/v1/logs/lab-allowlist/");
    setLabAllowlist(data.results || data || []);
  }, []);

  const loadLabHistory = useCallback(async () => {
    const data = await api.get(
      `/api/v1/logs/credential-tests/${buildQuery({ page_size: 100, include_hidden: true })}`
    );
    setLabHistory(data.results || data || []);
  }, []);

  const loadHits = useCallback(async (scanId) => {
    if (!scanId) {
      setHits([]);
      return;
    }
    const data = await api.get(
      `/api/v1/logs/scans/${scanId}/hits/${buildQuery({ page_size: 200 })}`
    );
    setHits(data.results || data || []);
  }, []);

  const labDomains = useMemo(() => {
    const values = new Set();
    hits.forEach((row) => {
      const direct = String(row.domain || "").trim().toLowerCase();
      if (direct) values.add(direct);
      try {
        const parsed = new URL(row.url || "");
        if (parsed.hostname) values.add(parsed.hostname.toLowerCase());
      } catch {
        // Keep the parser tolerant of raw log lines.
      }
    });
    return [...values].sort();
  }, [hits]);

  const labRows = useMemo(
    () => (labJob?.result_summary?.results || []).map((row, index) => ({
      ...row,
      id: `${labJob.id}-${index}`,
      target_url: labJob.target_url,
    })),
    [labJob]
  );

  const visibleLabHistory = useMemo(
    () => labHistory.filter((row) => showHiddenHistory || !row.is_hidden),
    [labHistory, showHiddenHistory]
  );

  const hiddenHistoryCount = useMemo(
    () => labHistory.filter((row) => row.is_hidden).length,
    [labHistory]
  );

  const startLabVerification = async () => {
    if (!scan?.id || !labDomain.trim()) return;
    setLabBusy(true);
    setError("");
    setMessage("");
    try {
      const domain = labDomain.trim().toLowerCase().replace(/\.$/, "");
      const targetUrl = labTargetUrl.trim() || `http://${domain}/`;
      const matchingHits = hits
        .filter((row) => {
          const rowDomain = String(row.domain || "").trim().toLowerCase().replace(/\.$/, "");
          return rowDomain === domain;
        })
        .slice(0, 20);
      if (!matchingHits.length) {
        throw new Error("No credential hits match this domain in the current scan.");
      }
      const job = await api.post(`/api/v1/logs/scans/${scan.id}/credential-test/`, {
        domain,
        target_url: targetUrl,
        hit_ids: matchingHits.map((row) => row.id),
      });
      setLabJob(job);
      await loadLabHistory();
      setMessage(`Lab verification queued for ${domain}.`);
    } catch (err) {
      setError(err.message || "Failed to start lab verification");
    } finally {
      setLabBusy(false);
    }
  };

  const addLabAllowlist = async () => {
    if (!labDomain.trim()) return;
    setAllowlistBusy(true);
    setError("");
    setMessage("");
    try {
      const entry = await api.post("/api/v1/logs/lab-allowlist/", {
        host: labDomain.trim(),
      });
      await loadLabAllowlist();
      setMessage(`${entry.host} is now on the lab allowlist.`);
    } catch (err) {
      setError(err.message || "Failed to add host to the lab allowlist");
    } finally {
      setAllowlistBusy(false);
    }
  };

  const removeLabAllowlist = async (entry) => {
    if (entry.source !== "ui") return;
    if (!window.confirm(`Remove ${entry.host} from the lab allowlist?`)) return;
    setAllowlistBusy(true);
    setError("");
    try {
      await api.delete(
        `/api/v1/logs/lab-allowlist/${buildQuery({ host: entry.host })}`
      );
      await loadLabAllowlist();
      setMessage(`${entry.host} was removed from the lab allowlist.`);
    } catch (err) {
      setError(err.message || "Failed to remove host from the lab allowlist");
    } finally {
      setAllowlistBusy(false);
    }
  };

  const setLabHistoryVisibility = async (row, isHidden) => {
    setHistoryBusy(true);
    setError("");
    try {
      const updated = await api.patch(
        `/api/v1/logs/credential-tests/${row.id}/visibility/`,
        { is_hidden: isHidden }
      );
      setLabHistory((current) => current.map((item) => (
        item.id === updated.id ? updated : item
      )));
      if (labJob?.id === updated.id) setLabJob(updated);
      setMessage(isHidden ? "Login history entry hidden." : "Login history entry restored.");
    } catch (err) {
      setError(err.message || "Failed to update login history visibility");
    } finally {
      setHistoryBusy(false);
    }
  };

  const deleteLabHistory = async (row) => {
    if (ACTIVE.has(row.status)) return;
    if (!window.confirm(`Delete login history job #${row.id}?`)) return;
    setHistoryBusy(true);
    setError("");
    try {
      await api.delete(`/api/v1/logs/credential-tests/${row.id}/`);
      setLabHistory((current) => current.filter((item) => item.id !== row.id));
      if (labJob?.id === row.id) setLabJob(null);
      setMessage(`Login history job #${row.id} was deleted.`);
    } catch (err) {
      setError(err.message || "Failed to delete login history");
    } finally {
      setHistoryBusy(false);
    }
  };

  const clearLabHistory = async () => {
    const deletable = labHistory.filter((row) => !ACTIVE.has(row.status));
    if (!deletable.length) return;
    if (!window.confirm(`Delete ${deletable.length} completed login history item(s)?`)) return;
    setHistoryBusy(true);
    setError("");
    try {
      const result = await api.delete("/api/v1/logs/credential-tests/clear/");
      await loadLabHistory();
      if (labJob && !ACTIVE.has(labJob.status)) setLabJob(null);
      setMessage(`${result?.deleted || 0} login history item(s) deleted.`);
    } catch (err) {
      setError(err.message || "Failed to clear login history");
    } finally {
      setHistoryBusy(false);
    }
  };

  const labResultColumns = useMemo(
    () => [
      {
        key: "target_url",
        label: "URL",
        nowrap: false,
        sx: { overflowWrap: "anywhere" },
      },
      { key: "username", label: "Username", truncate: true, maxWidth: 220 },
      {
        key: "success",
        label: "Result",
        render: (row) => (
          <Chip
            size="small"
            color={row.success ? "success" : "default"}
            label={row.success ? "Success" : "Not successful"}
          />
        ),
      },
      {
        key: "response_time_ms",
        label: "Response",
        render: (row) => (row.response_time_ms ? `${row.response_time_ms} ms` : "—"),
      },
    ],
    []
  );

  const labHistoryColumns = [
    {
      key: "created_at",
      label: "Time",
      nowrap: true,
      render: (row) => formatDateTime(row.created_at),
    },
    {
      key: "target_url",
      label: "URL",
      nowrap: false,
      sx: { overflowWrap: "anywhere" },
      render: (row) => row.target_url || row.target_domain || "—",
    },
    {
      key: "usernames",
      label: "Username(s)",
      nowrap: false,
      render: (row) => {
        const usernames = [...new Set(
          (row.result_summary?.results || [])
            .map((item) => String(item.username || "").trim())
            .filter(Boolean)
        )];
        return usernames.join(", ") || "—";
      },
    },
    {
      key: "status",
      label: "Status",
      render: (row) => (
        <Chip
          size="small"
          color={row.success_count ? "success" : ACTIVE.has(row.status) ? "warning" : "default"}
          label={`${row.status} · ${row.attempt_count || 0}/${row.success_count || 0}`}
        />
      ),
    },
    {
      key: "visibility",
      label: "Visibility",
      render: (row) => (
        <Chip
          size="small"
          variant="outlined"
          label={row.is_hidden ? "Hidden" : "Visible"}
        />
      ),
    },
    {
      key: "actions",
      label: "",
      width: 92,
      sticky: "right",
      render: (row) => (
        <Stack direction="row" spacing={0.25}>
          <IconButton
            size="small"
            disabled={historyBusy}
            title={row.is_hidden ? "Unhide history" : "Hide history"}
            onClick={() => setLabHistoryVisibility(row, !row.is_hidden)}
          >
            {row.is_hidden ? (
              <VisibilityOutlinedIcon fontSize="small" />
            ) : (
              <VisibilityOffOutlinedIcon fontSize="small" />
            )}
          </IconButton>
          <IconButton
            size="small"
            color="error"
            disabled={historyBusy || ACTIVE.has(row.status)}
            title={ACTIVE.has(row.status) ? "Active jobs cannot be deleted" : "Delete history"}
            onClick={() => deleteLabHistory(row)}
          >
            <DeleteOutlineIcon fontSize="small" />
          </IconButton>
        </Stack>
      ),
    },
  ];

  useEffect(() => {
    if (!isStaff) return undefined;
    let cancelled = false;
    (async () => {
      try {
        await Promise.all([
          loadUploads(),
          loadKept(),
          loadLimits(),
          loadLabAllowlist(),
          loadLabHistory(),
        ]);
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isStaff, loadUploads, loadKept, loadLimits, loadLabAllowlist, loadLabHistory]);

  useEffect(() => {
    if (!scan || !ACTIVE.has(scan.status)) return undefined;
    const timer = setInterval(async () => {
      try {
        const latest = await api.get(`/api/v1/logs/scans/${scan.id}/`);
        setScan(latest);
        if (!ACTIVE.has(latest.status)) {
          await loadHits(latest.id);
          setBusyScan(false);
          if (latest.status === "failed") {
            setError(latest.error_message || "Scan failed");
          } else {
            setMessage(`Found ${latest.hit_count} matches`);
          }
        }
      } catch (err) {
        setError(err.message || "Poll failed");
        setBusyScan(false);
      }
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [scan, loadHits]);

  useEffect(() => {
    if (!labJob?.id || !ACTIVE.has(labJob.status)) return undefined;
    const timer = setInterval(async () => {
      try {
        const latest = await api.get(`/api/v1/logs/credential-tests/${labJob.id}/`);
        setLabJob(latest);
        if (!ACTIVE.has(latest.status)) {
          await loadLabHistory();
          if (latest.status === "failed" || latest.status === "not_attempted") {
            setError(latest.error_message || "Lab verification failed");
          } else {
            setMessage(
              `Lab verification finished: ${latest.success_count || 0} successful login(s).`
            );
          }
        }
      } catch (err) {
        setError(err.message || "Lab verification poll failed");
      }
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [labJob?.id, labJob?.status, loadLabHistory]);

  const allSelected = uploads.length > 0 && selectedIds.size === uploads.length;

  const toggleAll = () => {
    if (allSelected) setSelectedIds(new Set());
    else setSelectedIds(new Set(uploads.map((row) => row.id)));
  };

  const toggleOne = (id) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const onPickFiles = (event) => {
    const selected = Array.from(event.target.files || []);
    const existing = pendingFiles;
    const remaining = Math.max(0, MAX_FILES_PER_UPLOAD - existing.length);
    const list = selected.slice(0, remaining);
    const valid = [];
    const rejected = [];
    const seen = new Set(existing.map(fileIdentity));
    selected.slice(remaining).forEach((file) => {
      rejected.push(`${file.name}: maximum ${MAX_FILES_PER_UPLOAD} files per upload`);
    });
    list.forEach((file) => {
      const key = fileIdentity(file);
      if (!file.name.toLowerCase().endsWith(".txt")) {
        rejected.push(`${file.name}: only .txt files are accepted`);
      } else if (file.size > maxUploadBytes) {
        rejected.push(`${file.name}: exceeds ${formatBytes(maxUploadBytes)}`);
      } else if (seen.has(key)) {
        rejected.push(`${file.name}: duplicate selection`);
      } else {
        seen.add(key);
        valid.push(file);
      }
    });
    setPendingFiles([...existing, ...valid]);
    setUploadProgress({ files: [] });
    setError(rejected.length ? rejected.join("; ") : "");
    event.target.value = "";
  };

  const updateFileProgress = (index, patch) => {
    setUploadProgress((current) => ({
      files: current.files.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item
      ),
    }));
  };

  const uploadChunkedFile = async (file, index, signal) => {
    const uploadId = createUploadId();
    const totalChunks = Math.ceil(file.size / UPLOAD_CHUNK_BYTES);
    let committedBytes = 0;

    for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex += 1) {
      const start = chunkIndex * UPLOAD_CHUNK_BYTES;
      const end = Math.min(file.size, start + UPLOAD_CHUNK_BYTES);
      const chunk = file.slice(start, end);
      let completed = false;

      for (let attempt = 0; attempt <= UPLOAD_RETRIES; attempt += 1) {
        let bestChunkLoaded = 0;
        updateFileProgress(index, {
          status: attempt ? "retrying" : "uploading",
          attempt: attempt + 1,
          chunk: chunkIndex + 1,
          totalChunks,
          error: "",
        });
        try {
          const form = new FormData();
          form.append("upload_id", uploadId);
          form.append("file_name", file.name);
          form.append("file_size", String(file.size));
          form.append("total_chunks", String(totalChunks));
          form.append("chunk_index", String(chunkIndex));
          form.append("chunk", chunk, `${file.name}.part${chunkIndex}`);
          await api.uploadWithProgress("/api/v1/logs/uploads/chunk/", form, {
            signal,
            onProgress: ({ loaded }) => {
              bestChunkLoaded = Math.max(bestChunkLoaded, loaded || 0);
              const loadedBytes = committedBytes + Math.min(bestChunkLoaded, chunk.size);
              updateFileProgress(index, {
                loaded: loadedBytes,
                total: file.size,
                percent: Math.min(100, Math.round((loadedBytes / file.size) * 100)),
              });
            },
          });
          committedBytes = end;
          updateFileProgress(index, {
            loaded: committedBytes,
            total: file.size,
            percent: Math.min(100, Math.round((committedBytes / file.size) * 100)),
          });
          completed = true;
          break;
        } catch (error) {
          if (error?.name === "AbortError") throw error;
          if (!isRetryableUploadError(error) || attempt >= UPLOAD_RETRIES) {
            const detail = error?.message || "Chunk upload failed";
            updateFileProgress(index, { status: "failed", error: detail });
            return { ok: false, error: detail };
          }
          await waitForRetry(600 * 2 ** attempt, signal);
        }
      }
      if (!completed) {
        return { ok: false, error: "Chunk upload failed" };
      }
    }

    updateFileProgress(index, {
      status: "done",
      loaded: file.size,
      total: file.size,
      percent: 100,
    });
    return { ok: true };
  };

  const uploadOneFile = async (file, index, signal) => {
    if (file.size > UPLOAD_CHUNK_BYTES) {
      return uploadChunkedFile(file, index, signal);
    }
    for (let attempt = 0; attempt <= UPLOAD_RETRIES; attempt += 1) {
      updateFileProgress(index, {
        status: attempt ? "retrying" : "uploading",
        attempt: attempt + 1,
        error: "",
      });
      try {
        const form = new FormData();
        form.append("files", file, file.name);
        const data = await api.uploadWithProgress(
          "/api/v1/logs/uploads/",
          form,
          {
            signal,
            onProgress: ({ loaded, total }) => {
              updateFileProgress(index, {
                loaded,
                total: total || file.size,
                percent: total ? Math.min(100, Math.round((loaded / total) * 100)) : null,
              });
            },
          }
        );
        const responseError = data?.errors?.[0]?.error;
        if (responseError && !data?.created?.length) {
          const validationError = new Error(responseError);
          validationError.status = 400;
          throw validationError;
        }
        updateFileProgress(index, {
          status: "done",
          loaded: file.size,
          total: file.size,
          percent: 100,
        });
        return { ok: true };
      } catch (error) {
        if (error?.name === "AbortError") throw error;
        if (!isRetryableUploadError(error) || attempt >= UPLOAD_RETRIES) {
          const detail = error?.message || "Upload failed";
          updateFileProgress(index, { status: "failed", error: detail });
          return { ok: false, error: detail };
        }
        await waitForRetry(600 * 2 ** attempt, signal);
      }
    }
    return { ok: false, error: "Upload failed" };
  };

  const uploadFiles = async () => {
    if (!pendingFiles.length) return;
    setBusyUpload(true);
    setError("");
    setMessage("");
    const files = [...pendingFiles];
    const controller = new AbortController();
    uploadControllerRef.current = controller;
    setUploadProgress({
      files: files.map((file, index) => ({
        key: fileKey(file, index),
        name: file.name,
        loaded: 0,
        total: file.size,
        percent: 0,
        status: "queued",
        attempt: 0,
        error: "",
      })),
    });
    try {
      let nextIndex = 0;
      const results = [];
      const worker = async () => {
        while (nextIndex < files.length) {
          const index = nextIndex;
          nextIndex += 1;
          const result = await uploadOneFile(files[index], index, controller.signal);
          results[index] = result;
        }
      };
      await Promise.all(
        Array.from(
          { length: Math.min(UPLOAD_CONCURRENCY, files.length) },
          () => worker()
        )
      );
      const failed = results
        .map((result, index) => (result?.ok ? null : { index, error: result?.error }))
        .filter(Boolean);
      const succeeded = files.length - failed.length;
      if (failed.length) {
        setPendingFiles(failed.map(({ index }) => files[index]));
        setError(
          `${failed.length} file(s) failed: ${failed
            .map(({ index, error }) => `${files[index].name}: ${error}`)
            .join("; ")}`
        );
      } else {
        setPendingFiles([]);
      }
      setMessage(`Uploaded ${succeeded}/${files.length} file(s)`);
      await loadUploads();
    } catch (err) {
      if (err?.name === "AbortError") {
        setError("Upload cancelled. You can retry the remaining files.");
        setPendingFiles(files);
      } else {
        setError(err.message || "Upload failed");
      }
    } finally {
      uploadControllerRef.current = null;
      setBusyUpload(false);
    }
  };

  const cancelUpload = () => {
    uploadControllerRef.current?.abort();
  };

  const startScan = async () => {
    if (!selectedIds.size) {
      setError("Select at least one file");
      return;
    }
    setBusyScan(true);
    setError("");
    setMessage("");
    setHits([]);
    try {
      const created = await api.post("/api/v1/logs/scans/", {
        keyword: keyword.trim(),
        upload_ids: [...selectedIds],
        async_mode: true,
      });
      setScan(created);
      setMessage("Scan queued…");
    } catch (err) {
      setBusyScan(false);
      setError(err.message || "Scan failed");
    }
  };

  const keepHit = async (hit) => {
    try {
      await api.post(`/api/v1/logs/hits/${hit.id}/keep/`, {});
      setHits((rows) =>
        rows.map((row) => (row.id === hit.id ? { ...row, is_kept: true } : row))
      );
      await loadKept();
    } catch (err) {
      setError(err.message || "Keep failed");
    }
  };

  const unkeepHit = async (hit) => {
    try {
      await api.post(`/api/v1/logs/hits/${hit.id}/unkeep/`, {});
      await loadKept();
      setHits((rows) =>
        rows.map((row) => (row.id === hit.id ? { ...row, is_kept: false } : row))
      );
    } catch (err) {
      setError(err.message || "Remove failed");
    }
  };

  const clearKept = async () => {
    try {
      await api.post("/api/v1/logs/hits/clear-kept/", {});
      await loadKept();
    } catch (err) {
      setError(err.message || "Clear failed");
    }
  };

  const deleteUpload = async (row) => {
    try {
      await api.delete(`/api/v1/logs/uploads/${row.id}/`);
      await loadUploads();
    } catch (err) {
      setError(err.message || "Delete failed");
    }
  };

  const uploadTotalBytes = uploadProgress.files.reduce(
    (total, item) => total + (Number(item.total) || 0),
    0
  );
  const uploadLoadedBytes = uploadProgress.files.reduce(
    (total, item) => total + Math.min(Number(item.loaded) || 0, Number(item.total) || 0),
    0
  );
  const uploadPercent = uploadTotalBytes
    ? Math.min(100, Math.round((uploadLoadedBytes / uploadTotalBytes) * 100))
    : 0;

  const hitColumns = useMemo(
    () => [
      {
        key: "keep",
        label: "Keep",
        width: 56,
        render: (row) => (
          <IconButton
            size="small"
            color={row.is_kept ? "success" : "primary"}
            onClick={() => (row.is_kept ? unkeepHit(row) : keepHit(row))}
            title={row.is_kept ? "Already kept" : "Keep record"}
          >
            <BookmarkAddOutlinedIcon fontSize="small" />
          </IconButton>
        ),
      },
      {
        key: "domain",
        label: "URL",
        nowrap: false,
        sx: { overflowWrap: "anywhere" },
        render: (row) => row.url || row.domain || "—",
      },
      {
        key: "username",
        label: "Username",
        truncate: true,
        maxWidth: 220,
        render: (row) => row.email || row.username || "—",
      },
      {
        key: "password",
        label: "Password",
        truncate: true,
        maxWidth: 180,
        render: (row) => row.password || "—",
      },
    ],
    []
  );

  const keptColumns = useMemo(
    () => [
      {
        key: "domain",
        label: "Domain",
        truncate: true,
        maxWidth: 220,
        render: (row) => row.url || row.domain || "—",
      },
      { key: "username", label: "Username", truncate: true, maxWidth: 120 },
      { key: "password", label: "Password", truncate: true, maxWidth: 140 },
      {
        key: "remove",
        label: "",
        width: 48,
        sticky: "right",
        render: (row) => (
          <IconButton size="small" color="error" onClick={() => unkeepHit(row)}>
            <CloseIcon fontSize="small" />
          </IconButton>
        ),
      },
    ],
    []
  );

  if (!isStaff) {
    return (
      <Box>
        <PageHeader
          title="Logs Scanner"
          subtitle="Staff only — upload and keyword-scan credential dumps."
        />
        <Alert severity="warning">Staff access required.</Alert>
      </Box>
    );
  }

  return (
    <Box>
      <PageHeader
        title="Logs Scanner"
        subtitle="Upload stealer .txt dumps (url:username:password), filter by keyword, and keep matches for follow-up."
      />

      {error ? (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>
          {error}
        </Alert>
      ) : null}
      {message ? (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setMessage("")}>
          {message}
        </Alert>
      ) : null}

      <Stack
        direction={{ xs: "column", md: "row" }}
        spacing={2}
        sx={{ mb: 2 }}
        alignItems="stretch"
      >
        <Paper variant="outlined" sx={{ p: 2, flex: 1 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            1. Upload files
          </Typography>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
            <Button
              variant="outlined"
              startIcon={<FolderOpenOutlinedIcon />}
              onClick={() => fileInputRef.current?.click()}
              disabled={busyUpload}
            >
              Choose files
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,text/plain"
              multiple
              hidden
              onChange={onPickFiles}
            />
            <Typography variant="body2" color="text.secondary">
              {pendingFiles.length
                ? `${pendingFiles.length} file(s) selected`
                : "No file chosen"}
            </Typography>
            <Button
              variant="contained"
              disabled={!pendingFiles.length || busyUpload}
              onClick={uploadFiles}
            >
              {busyUpload ? <CircularProgress size={18} /> : "Upload"}
            </Button>
            {busyUpload ? (
              <Button size="small" color="warning" onClick={cancelUpload}>
                Cancel
              </Button>
            ) : null}
          </Stack>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
            Maximum {MAX_FILES_PER_UPLOAD} files per upload · up to {UPLOAD_CONCURRENCY} files upload in parallel · files over {formatBytes(UPLOAD_CHUNK_BYTES)} use resumable chunks · up to {formatBytes(maxUploadBytes)} per file.
          </Typography>
          {uploadProgress.files.length ? (
            <Box sx={{ mt: 1.5 }}>
              <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  Uploading {uploadProgress.files.filter((item) => item.status === "done").length}/
                  {uploadProgress.files.length} files · {uploadPercent}%
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {formatBytes(uploadLoadedBytes)} / {formatBytes(uploadTotalBytes)}
                </Typography>
              </Stack>
              <LinearProgress
                variant="determinate"
                value={uploadPercent}
                sx={{ height: 7, borderRadius: 4 }}
              />
              <Box sx={{ mt: 1, maxHeight: 150, overflow: "auto" }}>
                <Stack spacing={0.7}>
                  {uploadProgress.files.map((item) => (
                    <Box key={item.key}>
                      <Stack direction="row" justifyContent="space-between" spacing={1}>
                        <Typography variant="caption" noWrap title={item.name} sx={{ minWidth: 0 }}>
                          {item.name}
                        </Typography>
                        <Typography
                          variant="caption"
                          color={item.status === "failed" ? "error" : "text.secondary"}
                          sx={{ whiteSpace: "nowrap" }}
                        >
                          {item.status === "done"
                            ? "Done"
                            : item.status === "failed"
                              ? "Failed"
                              : item.status === "retrying"
                                ? `Retry ${item.attempt}/${UPLOAD_RETRIES + 1}`
                                : `${item.percent || 0}%`}
                        </Typography>
                      </Stack>
                      <LinearProgress
                        variant="determinate"
                        color={item.status === "failed" ? "error" : "primary"}
                        value={item.percent || 0}
                        sx={{ height: 4, borderRadius: 3 }}
                      />
                    </Box>
                  ))}
                </Stack>
              </Box>
            </Box>
          ) : null}
        </Paper>

        <Paper variant="outlined" sx={{ p: 2, flex: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            2. Select files & scan
          </Typography>
          <Stack
            direction={{ xs: "column", sm: "row" }}
            spacing={1}
            sx={{ mb: 1.5 }}
            alignItems={{ sm: "center" }}
          >
            <TextField
              size="small"
              type="date"
              label="From"
              InputLabelProps={{ shrink: true }}
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
            />
            <TextField
              size="small"
              type="date"
              label="To"
              InputLabelProps={{ shrink: true }}
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
            />
            <TextField
              size="small"
              fullWidth
              label="Keyword"
              placeholder="e.g. .gov.vn"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
            />
            <Button
              variant="contained"
              startIcon={
                busyScan ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <AutoFixHighIcon />
                )
              }
              disabled={busyScan || !selectedIds.size}
              onClick={startScan}
              sx={{ whiteSpace: "nowrap" }}
            >
              Scan now
            </Button>
          </Stack>

          <Box
            sx={{
              maxHeight: 220,
              overflow: "auto",
              border: "1px solid",
              borderColor: "divider",
              borderRadius: 1,
            }}
          >
            <Stack
              direction="row"
              alignItems="center"
              sx={{ px: 1, py: 0.5, bgcolor: "action.hover" }}
            >
              <Checkbox
                size="small"
                checked={allSelected}
                indeterminate={selectedIds.size > 0 && !allSelected}
                onChange={toggleAll}
              />
              <Typography variant="caption" color="text.secondary">
                {uploads.length} file(s)
              </Typography>
            </Stack>
            {uploads.map((row) => (
              <Stack
                key={row.id}
                direction="row"
                alignItems="center"
                spacing={1}
                sx={{ px: 1, py: 0.35, borderTop: "1px solid", borderColor: "divider" }}
              >
                <Checkbox
                  size="small"
                  checked={selectedIds.has(row.id)}
                  onChange={() => toggleOne(row.id)}
                />
                <Typography variant="body2" sx={{ flex: 1 }} noWrap title={row.original_name}>
                  {row.original_name}
                </Typography>
                <Chip size="small" label={formatBytes(row.size_bytes)} variant="outlined" />
                <Typography variant="caption" color="text.secondary" sx={{ minWidth: 84 }}>
                  {formatDate(row.created_at)}
                </Typography>
                <IconButton size="small" onClick={() => deleteUpload(row)} title="Delete">
                  <DeleteOutlineIcon fontSize="small" />
                </IconButton>
              </Stack>
            ))}
            {!uploads.length ? (
              <Typography color="text.secondary" sx={{ p: 2 }}>
                No uploads yet.
              </Typography>
            ) : null}
          </Box>
        </Paper>
      </Stack>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems={{ md: "center" }}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle2">Lab login verification</Typography>
            <Typography variant="caption" color="text.secondary">
              Allowlisted lab targets only · max 20 pairs · single-threaded · passwords are not saved in results.
            </Typography>
          </Box>
          <TextField
            size="small"
            label="Domain from scan"
            value={labDomain}
            onChange={(event) => setLabDomain(event.target.value)}
            inputProps={{ list: "logs-scanner-lab-domains" }}
            disabled={!scan || ACTIVE.has(scan.status) || labBusy || allowlistBusy}
          />
          <datalist id="logs-scanner-lab-domains">
            {labDomains.map((domain) => <option key={domain} value={domain} />)}
          </datalist>
          <Button
            variant="outlined"
            size="small"
            disabled={!labDomain.trim() || allowlistBusy || ACTIVE.has(labJob?.status)}
            onClick={addLabAllowlist}
          >
            {allowlistBusy ? <CircularProgress size={18} /> : "Add to allowlist"}
          </Button>
          <TextField
            size="small"
            label="Lab target URL"
            placeholder="http://app.test/login"
            value={labTargetUrl}
            onChange={(event) => setLabTargetUrl(event.target.value)}
            disabled={!scan || ACTIVE.has(scan.status) || labBusy || allowlistBusy}
          />
          <Button
            variant="contained"
            color="warning"
            disabled={!scan || ACTIVE.has(scan.status) || !labDomain.trim() || labBusy}
            onClick={startLabVerification}
          >
            {labBusy || ACTIVE.has(labJob?.status) ? <CircularProgress size={18} color="inherit" /> : "Verify in lab"}
          </Button>
        </Stack>
        <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap sx={{ mt: 1.25 }} alignItems="center">
          <Typography variant="caption" color="text.secondary">Lab allowlist:</Typography>
          {labAllowlist.length ? labAllowlist.map((entry) => (
            <Chip
              key={entry.host}
              size="small"
              variant={entry.host === labDomain.trim().toLowerCase().replace(/\.$/, "") ? "filled" : "outlined"}
              color={entry.source === "config" ? "default" : "info"}
              label={entry.host}
              onClick={() => setLabDomain(entry.host)}
              onDelete={entry.source === "ui" ? () => removeLabAllowlist(entry) : undefined}
              deleteIcon={entry.source === "ui" ? <CloseIcon /> : undefined}
              disabled={allowlistBusy}
            />
          )) : (
            <Typography variant="caption" color="text.secondary">No lab hosts added yet.</Typography>
          )}
        </Stack>
        {labJob ? (
          <Box sx={{ mt: 1.5 }}>
            <Typography variant="caption" color="text.secondary">
              Job #{labJob.id} · {labJob.target_url} · {labJob.status} · {labJob.attempt_count || 0} attempt(s) · {labJob.success_count || 0} success(es)
            </Typography>
            <DataTable columns={labResultColumns} rows={labRows} empty="No result rows yet" />
          </Box>
        ) : null}
        <Box sx={{ mt: 2 }}>
          <Stack
            direction={{ xs: "column", sm: "row" }}
            spacing={1}
            justifyContent="space-between"
            alignItems={{ sm: "center" }}
            sx={{ mb: 1 }}
          >
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="subtitle2">Login attempt history</Typography>
              <Chip size="small" label={String(visibleLabHistory.length)} />
            </Stack>
            <Stack direction="row" spacing={1}>
              <Button
                size="small"
                variant="outlined"
                startIcon={showHiddenHistory ? <VisibilityOffOutlinedIcon /> : <VisibilityOutlinedIcon />}
                disabled={!hiddenHistoryCount || historyBusy}
                onClick={() => setShowHiddenHistory((current) => !current)}
              >
                {showHiddenHistory ? "Hide hidden" : `Show hidden (${hiddenHistoryCount})`}
              </Button>
              <Button
                size="small"
                color="error"
                startIcon={<DeleteOutlineIcon />}
                disabled={historyBusy || !labHistory.some((row) => !ACTIVE.has(row.status))}
                onClick={clearLabHistory}
              >
                Clear history
              </Button>
            </Stack>
          </Stack>
          <DataTable
            columns={labHistoryColumns}
            rows={visibleLabHistory}
            loading={historyBusy && !labHistory.length}
            empty={showHiddenHistory ? "No login history yet" : "No visible login history"}
          />
        </Box>
      </Paper>

      <Stack direction={{ xs: "column", lg: "row" }} spacing={2} alignItems="stretch">
        <Paper variant="outlined" sx={{ p: 2, flex: 1.4, minHeight: 280 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle1">
              {scan && ACTIVE.has(scan.status)
                ? `Scanning… (${scan.status})`
                : scan
                  ? "Results"
                  : "Ready to scan"}
            </Typography>
            <Chip
              size="small"
              label={`Found: ${hits.length}${scan?.hit_count != null && scan.hit_count !== hits.length ? ` / ${scan.hit_count}` : ""}`}
            />
          </Stack>
          <DataTable
            columns={hitColumns}
            rows={hits}
            empty="No results yet"
            loading={busyScan && !hits.length}
          />
        </Paper>

        <Paper variant="outlined" sx={{ p: 2, flex: 1, minHeight: 280 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="subtitle1">Kept records</Typography>
              <Chip size="small" color="primary" label={String(kept.length)} />
            </Stack>
            <Button
              size="small"
              color="error"
              startIcon={<DeleteOutlineIcon />}
              disabled={!kept.length}
              onClick={clearKept}
            >
              Clear all
            </Button>
          </Stack>
          <DataTable columns={keptColumns} rows={kept} empty="No kept records" />
        </Paper>
      </Stack>
    </Box>
  );
}
