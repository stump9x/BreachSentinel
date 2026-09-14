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
  MenuItem,
} from "@mui/material";
import AddCircleOutlineIcon from "@mui/icons-material/AddCircleOutline";
import BookmarkAddOutlinedIcon from "@mui/icons-material/BookmarkAddOutlined";
import CloseIcon from "@mui/icons-material/Close";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import StarBorderIcon from "@mui/icons-material/StarBorder";
import StarIcon from "@mui/icons-material/Star";
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
const MAX_SCAN_WAIT_ATTEMPTS = 600;

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
  const [warning, setWarning] = useState("");
  const [maxUploadBytes, setMaxUploadBytes] = useState(DEFAULT_MAX_UPLOAD_BYTES);
  const [uploadProgress, setUploadProgress] = useState({ files: [] });
  const [scan, setScan] = useState(null);
  const [hits, setHits] = useState([]);
  const [kept, setKept] = useState([]);
  const [pendingFiles, setPendingFiles] = useState([]);
  const uploadControllerRef = useRef(null);
  const [labDomain, setLabDomain] = useState("");
  const [labTargetUrl, setLabTargetUrl] = useState("");
  const [labProxyUrl, setLabProxyUrl] = useState("");
  const [labProxyUsername, setLabProxyUsername] = useState("");
  const [labProxyPassword, setLabProxyPassword] = useState("");
  const [labProxyProfiles, setLabProxyProfiles] = useState([]);
  // null means the initial default has not been resolved yet; an empty string
  // is an explicit user choice to run directly without a proxy.
  const [labProxyProfileId, setLabProxyProfileId] = useState(null);
  const [labProxyProfileName, setLabProxyProfileName] = useState("");
  const [proxyProfileBusy, setProxyProfileBusy] = useState(false);
  const [proxyEditorOpen, setProxyEditorOpen] = useState(false);
  const [labSelectedDomains, setLabSelectedDomains] = useState([]);
  const [labTargetUrls, setLabTargetUrls] = useState({});
  const [labDomainHistory, setLabDomainHistory] = useState([]);
  const [labJob, setLabJob] = useState(null);
  const [labJobs, setLabJobs] = useState([]);
  const [labBusy, setLabBusy] = useState(false);
  const [labAllowlist, setLabAllowlist] = useState([]);
  const [allowlistBusy, setAllowlistBusy] = useState(false);
  const [labHistory, setLabHistory] = useState([]);
  const [historyBusy, setHistoryBusy] = useState(false);
  // Keep the history panels compact after every page load; users can expand
  // either panel with its arrow when they need to review entries.
  const [historyExpanded, setHistoryExpanded] = useState(false);
  const [domainHistoryExpanded, setDomainHistoryExpanded] = useState(false);
  const labVerifySubmittingRef = useRef(false);

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

  const loadLabDomainHistory = useCallback(async () => {
    const data = await api.get("/api/v1/logs/domains/");
    setLabDomainHistory(Array.isArray(data) ? data : (data.results || []));
  }, []);

  const loadLabProxyProfiles = useCallback(async () => {
    const data = await api.get("/api/v1/logs/proxy-profiles/");
    const rows = Array.isArray(data) ? data : (data.results || []);
    setLabProxyProfiles(rows);
    setLabProxyProfileId((current) => (
      current === null
        ? String(rows.find((row) => row.is_default)?.id || "")
        : current
    ));
    return rows;
  }, []);

  const selectLabProxyProfile = (profileId) => {
    const value = String(profileId || "");
    setLabProxyProfileId(value);
    if (value) {
      setLabProxyUrl("");
      setLabProxyUsername("");
      setLabProxyPassword("");
      setProxyEditorOpen(false);
    }
  };

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

  const waitForLogScan = useCallback(async (scanId) => {
    let latest = await api.get(`/api/v1/logs/scans/${scanId}/`);
    for (let attempt = 0; attempt < MAX_SCAN_WAIT_ATTEMPTS; attempt += 1) {
      if (!ACTIVE.has(latest.status)) return latest;
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
      latest = await api.get(`/api/v1/logs/scans/${scanId}/`);
    }
    throw new Error("Scan bổ sung mất quá nhiều thời gian, vui lòng kiểm tra lại lịch sử scan.");
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

  const labDomainOptions = useMemo(() => {
    const options = new Map(
      labDomainHistory.map((row) => [String(row.domain || "").trim().toLowerCase().replace(/\.$/, ""), {
        domain: String(row.domain || "").trim().toLowerCase().replace(/\.$/, ""),
        hit_count: Number(row.hit_count) || 0,
        scan_id: row.latest_scan_id,
        latest_scanned_at: row.latest_scanned_at,
      }])
    );
    labDomains.forEach((domain) => {
      const existing = options.get(domain);
      if (existing) return;
      const hitCount = hits.filter((row) => {
        let rowDomain = String(row.domain || "").trim().toLowerCase().replace(/\.$/, "");
        if (!rowDomain) {
          try {
            rowDomain = new URL(row.url || "").hostname.toLowerCase().replace(/\.$/, "");
          } catch {
            rowDomain = "";
          }
        }
        return rowDomain === domain;
      }).length;
      options.set(domain, {
        domain,
        hit_count: hitCount,
        scan_id: scan?.id,
        latest_scanned_at: scan?.completed_at || scan?.created_at,
      });
    });
    return [...options.values()]
      .filter((row) => row.domain)
      .sort((a, b) => {
        const timeDiff = new Date(b.latest_scanned_at || 0).getTime() - new Date(a.latest_scanned_at || 0).getTime();
        return timeDiff || a.domain.localeCompare(b.domain);
      })
      .slice(0, 20);
  }, [labDomainHistory, labDomains, hits, scan?.id, scan?.completed_at, scan?.created_at]);

  useEffect(() => {
    const available = new Set(labDomainOptions.map((row) => row.domain));
    setLabSelectedDomains((current) => current.filter((domain) => available.has(domain)));
    setLabTargetUrls((current) => Object.fromEntries(
      Object.entries(current).filter(([domain]) => available.has(domain))
    ));
  }, [labDomainOptions]);

  const toggleLabDomain = (domain) => {
    setLabSelectedDomains((current) => (
      current.includes(domain)
        ? current.filter((item) => item !== domain)
        : [...current, domain]
    ));
    setLabDomain(domain);
  };

  const toggleAllLabDomains = () => {
    setLabSelectedDomains((current) => (
      current.length === labDomainOptions.length ? [] : labDomainOptions.map((row) => row.domain)
    ));
  };

  const labRows = useMemo(
    () => (labJob?.result_summary?.results || []).map((row, index) => ({
      ...row,
      id: `${labJob.id}-${index}`,
      target_url: labJob.target_url,
    })),
    [labJob]
  );

  const startLabVerification = async () => {
    if (labVerifySubmittingRef.current) return;
    const selectedDomains = [...new Set(
      labSelectedDomains
        .map((domain) => String(domain || "").trim().toLowerCase().replace(/\.$/, ""))
        .filter(Boolean)
    )];
    if (!selectedIds.size || !selectedDomains.length) {
      setError("Hãy chọn ít nhất một file logs và một domain trước khi verify.");
      return;
    }
    labVerifySubmittingRef.current = true;
    setLabBusy(true);
    setError("");
    setMessage("");
    setWarning("");
    // The queue panel represents only the current batch; older attempts stay in history.
    setLabJobs([]);
    setLabJob(null);
    try {
      const optionByDomain = new Map(labDomainOptions.map((row) => [row.domain, row]));
      const allowlistedHosts = new Set(labAllowlist.map((entry) => (
        String(entry.host || "").trim().toLowerCase().replace(/\.$/, "")
      )).filter(Boolean));
      const skippedDomains = selectedDomains.filter((domain) => !allowlistedHosts.has(domain));
      const verifiableDomains = selectedDomains.filter((domain) => allowlistedHosts.has(domain));
      if (!verifiableDomains.length) {
        setLabDomain(skippedDomains[0] || selectedDomains[0] || "");
        setWarning("Các domain đã chọn chưa có trong Allowlist nên chưa có domain nào được verify.");
        return;
      }
      const selectedUploadIds = [...selectedIds].map(Number);
      const selectedUploadSet = new Set(selectedUploadIds.map(String));
      const sourceScanIds = [...new Set(
        verifiableDomains
          .map((domain) => optionByDomain.get(domain)?.scan_id)
          .filter(Boolean)
          .map(String)
      )];
      const sourceScanRows = await Promise.all(sourceScanIds.map(async (scanId) => (
        [scanId, await api.get(`/api/v1/logs/scans/${scanId}/`)]
      )));
      const sourceScans = new Map(sourceScanRows);
      const sourceHits = new Map();
      const loadSourceHits = async (scanId, domain) => {
        const normalizedDomain = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
        const key = `${scanId}:${normalizedDomain}`;
        if (!sourceHits.has(key)) {
          const data = await api.get(`/api/v1/logs/scans/${scanId}/hits/${buildQuery({ page_size: 200, domain: normalizedDomain })}`);
          sourceHits.set(key, data.results || data || []);
        }
        return sourceHits.get(key);
      };
      const matchesSelectedFiles = (source) => {
        if (!source || source.status !== "completed") return false;
        const sourceUploads = new Set((source.upload_ids || []).map(String));
        return sourceUploads.size === selectedUploadSet.size
          && [...sourceUploads].every((id) => selectedUploadSet.has(id));
      };
      const domainsNeedingScan = verifiableDomains.filter((domain) => {
        const option = optionByDomain.get(domain);
        return !option?.scan_id || !matchesSelectedFiles(sourceScans.get(String(option.scan_id)));
      });

      if (domainsNeedingScan.length) {
        setBusyScan(true);
        setMessage(`Đang scan ${domainsNeedingScan.length} domain chưa có kết quả trên các file đã chọn…`);
        const created = await api.post("/api/v1/logs/scans/", {
          // Use a full scan so every selected domain can be resolved in one pass.
          keyword: "",
          upload_ids: selectedUploadIds,
          async_mode: true,
        });
        setScan(created);
        const completed = await waitForLogScan(created.id);
        setScan(completed);
        setBusyScan(false);
        if (completed.status !== "completed") {
          throw new Error(completed.error_message || "Scan bổ sung thất bại.");
        }
        domainsNeedingScan.forEach((domain) => {
          sourceScans.set(String(completed.id), completed);
          optionByDomain.set(domain, {
            ...(optionByDomain.get(domain) || {}),
            domain,
            scan_id: completed.id,
          });
        });
        await loadHits(completed.id);
        await loadLabDomainHistory();
      }

      await Promise.all(verifiableDomains.map(async (domain) => {
        const option = optionByDomain.get(domain);
        if (option?.scan_id) await loadSourceHits(option.scan_id, domain);
      }));
      const groupedTargets = new Map();
      verifiableDomains.forEach((domain) => {
        const option = optionByDomain.get(domain);
        if (!option?.scan_id) throw new Error(`Không tìm thấy scan nguồn cho domain ${domain}.`);
        const targetUrl = verifiableDomains.length === 1 && labTargetUrl.trim()
          ? labTargetUrl.trim()
          : (labTargetUrls[domain] || `http://${domain}/`);
        const rows = sourceHits.get(`${option.scan_id}:${domain}`);
        if (!rows) throw new Error(`Không tải được credential của domain ${domain}.`);
        const domainHits = rows.filter((row) => {
          let rowDomain = String(row.domain || "").trim().toLowerCase().replace(/\.$/, "");
          if (!rowDomain) {
            try {
              rowDomain = new URL(row.url || "").hostname.toLowerCase().replace(/\.$/, "");
            } catch {
              rowDomain = "";
            }
          }
          return rowDomain === domain
            && String(row.password || "")
            && String(row.email || row.username || "").trim();
        });
        if (!domainHits.length) throw new Error(`Không có credential hợp lệ cho domain ${domain}.`);
        const group = groupedTargets.get(String(option.scan_id)) || [];
        domainHits.slice(0, 20).forEach((hit) => {
          group.push({ domain, target_url: targetUrl, hit_ids: [hit.id] });
        });
        groupedTargets.set(String(option.scan_id), group);
      });
      const proxyPayload = labProxyProfileId
        ? { proxy_profile_id: Number(labProxyProfileId) }
        : {
            proxy_url: labProxyUrl.trim(),
            proxy_username: labProxyUsername,
            proxy_password: labProxyPassword,
          };
      const requests = [];
      [...groupedTargets.entries()].forEach(([scanId, targets]) => {
        for (let index = 0; index < targets.length; index += 10) {
          requests.push(api.post(
            `/api/v1/logs/scans/${scanId}/credential-test-batch/`,
            { targets: targets.slice(index, index + 10), ...proxyPayload }
          ));
        }
      });
      const results = await Promise.all(requests);
      const jobs = results.flatMap((result) => result.jobs || []);
      setLabJobs(jobs);
      setLabJob(jobs[0] || null);
      setLabProxyPassword("");
      await loadLabHistory();
      setMessage(`Đã xếp hàng ${jobs.length} credential thuộc ${verifiableDomains.length} domain.`);
      if (skippedDomains.length) {
        setLabDomain(skippedDomains[0]);
        setWarning(`Đã bỏ qua ${skippedDomains.length} domain chưa có trong Allowlist: ${skippedDomains.join(", ")}. Bạn có thể thêm từng domain rồi verify lại.`);
      }
    } catch (err) {
      setError(err.message || "Failed to start lab verification");
    } finally {
      setBusyScan(false);
      setLabBusy(false);
      labVerifySubmittingRef.current = false;
    }
  };

  const saveLabProxyProfile = async () => {
    if (!labProxyUrl.trim() || !labProxyProfileName.trim()) return;
    setProxyProfileBusy(true);
    setError("");
    try {
      const profile = await api.post("/api/v1/logs/proxy-profiles/", {
        name: labProxyProfileName.trim(),
        proxy_url: labProxyUrl.trim(),
        proxy_username: labProxyUsername,
        proxy_password: labProxyPassword,
        is_default: true,
      });
      setLabProxyProfiles((current) => [
        profile,
        ...current.filter((row) => String(row.id) !== String(profile.id)),
      ].map((row, index) => ({ ...row, is_default: index === 0 })));
      setLabProxyProfileId(String(profile.id));
      setLabProxyUrl("");
      setLabProxyUsername("");
      setLabProxyProfileName("");
      setLabProxyPassword("");
      setProxyEditorOpen(false);
      setMessage(`Proxy ${profile.name} đã được ghim và mã hóa an toàn.`);
    } catch (err) {
      setError(err.message || "Failed to save proxy profile");
    } finally {
      setProxyProfileBusy(false);
    }
  };

  const deleteLabProxyProfile = async (profileId = labProxyProfileId) => {
    if (!profileId) return;
    const profile = labProxyProfiles.find((row) => String(row.id) === String(profileId));
    if (!window.confirm(`Bỏ proxy đã ghim${profile?.name ? ` ${profile.name}` : ""}?`)) return;
    setProxyProfileBusy(true);
    try {
      await api.delete(`/api/v1/logs/proxy-profiles/${profileId}/`);
      if (String(profileId) === String(labProxyProfileId)) setLabProxyProfileId("");
      setLabProxyProfiles((current) => current.filter((row) => String(row.id) !== String(profileId)));
      await loadLabProxyProfiles();
      setMessage("Đã bỏ proxy đã ghim.");
    } catch (err) {
      setError(err.message || "Failed to delete proxy profile");
    } finally {
      setProxyProfileBusy(false);
    }
  };

  const setDefaultLabProxyProfile = async (profileId) => {
    if (!profileId) return;
    setProxyProfileBusy(true);
    setError("");
    try {
      const profile = await api.post(`/api/v1/logs/proxy-profiles/${profileId}/set-default/`, {});
      setLabProxyProfiles((current) => current.map((row) => ({
        ...row,
        is_default: String(row.id) === String(profile.id),
      })));
      setLabProxyProfileId(String(profile.id));
      setMessage(`Đã đặt ${profile.name} làm proxy mặc định.`);
    } catch (err) {
      setError(err.message || "Failed to set default proxy");
    } finally {
      setProxyProfileBusy(false);
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

  const deleteLabHistory = async (row) => {
    if (ACTIVE.has(row.status)) return;
    if (!window.confirm(`Delete login history job #${row.id}?`)) return;
    setHistoryBusy(true);
    setError("");
    try {
      await api.delete(`/api/v1/logs/credential-tests/${row.id}/`);
      setLabHistory((current) => current.filter((item) => item.id !== row.id));
      setLabJobs((current) => current.filter((item) => item.id !== row.id));
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
      setLabJobs([]);
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
      {
        key: "external_ip",
        label: "Login IP",
        render: (row) => row.external_ip || (
          row.external_ip_status === "proxy_probe_failed"
            ? "Không lấy được IP proxy"
            : "Unknown"
        ),
      },
      {
        key: "proxy_server",
        label: "Proxy",
        nowrap: false,
        sx: { overflowWrap: "anywhere" },
        render: (row) => row.proxy_server || "Direct",
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
      key: "external_ips",
      label: "Login IP(s)",
      nowrap: false,
      render: (row) => {
        const addresses = [...new Set(
          (row.result_summary?.results || [])
            .map((item) => String(item.external_ip || "").trim())
            .filter(Boolean)
        )];
        if (addresses.length) return addresses.join(", ");
        const hasProxyProbeFailure = (row.result_summary?.results || [])
          .some((item) => item.external_ip_status === "proxy_probe_failed");
        return hasProxyProbeFailure ? "Không lấy được IP proxy" : "Unknown";
      },
    },
    {
      key: "proxy_url",
      label: "Proxy",
      nowrap: false,
      sx: { overflowWrap: "anywhere" },
      render: (row) => [row.proxy_profile_name, row.proxy_display || row.result_summary?.proxy]
        .filter(Boolean)
        .join(" · ") || "Direct",
    },
    {
      key: "actions",
      label: "",
      width: 48,
      sticky: "right",
      render: (row) => (
        <IconButton
          size="small"
          color="error"
          disabled={historyBusy || ACTIVE.has(row.status)}
          title={ACTIVE.has(row.status) ? "Active jobs cannot be deleted" : "Delete history"}
          onClick={() => deleteLabHistory(row)}
        >
          <DeleteOutlineIcon fontSize="small" />
        </IconButton>
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
          loadLabDomainHistory(),
          loadLabProxyProfiles(),
          loadLabHistory(),
        ]);
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isStaff, loadUploads, loadKept, loadLimits, loadLabAllowlist, loadLabDomainHistory, loadLabProxyProfiles, loadLabHistory]);

  useEffect(() => {
    if (!scan || !ACTIVE.has(scan.status)) return undefined;
    const timer = setInterval(async () => {
      try {
        const latest = await api.get(`/api/v1/logs/scans/${scan.id}/`);
        setScan(latest);
        if (!ACTIVE.has(latest.status)) {
          await loadHits(latest.id);
          await loadLabDomainHistory();
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
  }, [scan, loadHits, loadLabDomainHistory]);

  useEffect(() => {
    const activeJobs = labJobs.filter((job) => ACTIVE.has(job.status));
    if (!activeJobs.length) return undefined;
    const timer = setInterval(async () => {
      try {
        const latestJobs = await Promise.all(
          activeJobs.map((job) => api.get(`/api/v1/logs/credential-tests/${job.id}/`))
        );
        setLabJobs((current) => current.map((job) => (
          latestJobs.find((latest) => latest.id === job.id) || job
        )));
        setLabJob((current) => {
          const latest = latestJobs.find((item) => item.id === current?.id);
          return latest || current;
        });
        if (latestJobs.some((latest) => !ACTIVE.has(latest.status))) {
          await loadLabHistory();
          const finished = latestJobs.filter((latest) => !ACTIVE.has(latest.status));
          const failed = finished.find((latest) => latest.status === "failed" || latest.status === "not_attempted");
          if (failed) setError(failed.error_message || "Lab verification failed");
          else setMessage(`Đã hoàn tất ${finished.length} job kiểm thử login.`);
        }
      } catch (err) {
        setError(err.message || "Lab verification poll failed");
      }
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [labJobs, loadLabHistory]);

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
        render: (row) => {
          let domain = String(row.domain || "").trim().toLowerCase().replace(/\.$/, "");
          if (!domain) {
            try {
              domain = new URL(row.url || "").hostname.toLowerCase().replace(/\.$/, "");
            } catch {
              domain = "";
            }
          }
          const selected = domain && labSelectedDomains.includes(domain);
          return (
            <Stack direction="row" spacing={0.5} alignItems="center">
              {domain ? (
                <Checkbox
                  size="small"
                  checked={Boolean(selected)}
                  onClick={(event) => event.stopPropagation()}
                  onChange={() => toggleLabDomain(domain)}
                  title={`Chọn domain ${domain} để kiểm thử`}
                />
              ) : null}
              <Typography variant="body2" sx={{ overflowWrap: "anywhere" }}>
                {row.url || row.domain || "—"}
              </Typography>
            </Stack>
          );
        },
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
    [labSelectedDomains]
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
      {warning ? (
        <Alert severity="warning" sx={{ mb: 2 }} onClose={() => setWarning("")}>
          {warning}
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

      <Stack direction={{ xs: "column", lg: "row" }} spacing={2} alignItems="stretch" sx={{ mb: 2 }}>
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

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction="column" spacing={1.5}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle2">Lab login verification</Typography>
            <Typography variant="caption" color="text.secondary">
              Allowlisted lab targets only · max 20 pairs · single-threaded · passwords are not saved in results.
            </Typography>
          </Box>
          <TextField
            size="small"
            label="Domain from scan"
            select
            value={labDomain}
            onChange={(event) => setLabDomain(event.target.value)}
            disabled={labBusy || allowlistBusy}
            InputLabelProps={{ shrink: true }}
            SelectProps={{ displayEmpty: true }}
          >
            <MenuItem value="" aria-label="Clear selected domain"> </MenuItem>
            {labDomainOptions.map((row) => (
              <MenuItem key={row.domain} value={row.domain}>{row.domain}</MenuItem>
            ))}
          </TextField>
          <Button
            variant="outlined"
            size="small"
            disabled={!labDomain.trim() || labAllowlist.some((entry) => (
              String(entry.host || "").trim().toLowerCase().replace(/\.$/, "")
                === labDomain.trim().toLowerCase().replace(/\.$/, "")
            )) || allowlistBusy || labJobs.some((job) => ACTIVE.has(job.status))}
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
            helperText={labSelectedDomains.length > 1 ? "Chỉ dùng khi chọn đúng 1 domain; nhiều domain sẽ dùng URL mặc định." : ""}
            disabled={labBusy || allowlistBusy || labSelectedDomains.length > 1}
          />
          <Paper
            variant="outlined"
            sx={{ flex: "1 1 100%", p: 1.25, borderRadius: 2, bgcolor: "background.default" }}
          >
            <Stack direction="row" spacing={0.75} alignItems="center" justifyContent="space-between">
              <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
                <IconButton
                  size="small"
                  title={domainHistoryExpanded ? "Thu gọn domain đã scan" : "Mở rộng domain đã scan"}
                  aria-label={domainHistoryExpanded ? "Thu gọn domain đã scan" : "Mở rộng domain đã scan"}
                  onClick={() => setDomainHistoryExpanded((current) => !current)}
                >
                  {domainHistoryExpanded ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
                </IconButton>
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="subtitle2">Domains từ scan đã quét</Typography>
                  <Typography variant="caption" color="text.secondary">
                    20 domain scan gần nhất, mới nhất xếp trên. Đã chọn {labSelectedDomains.length}/{labDomainOptions.length}.
                  </Typography>
                </Box>
              </Stack>
              {domainHistoryExpanded ? (
                <Stack direction="row" spacing={0.75}>
                  <Button size="small" onClick={toggleAllLabDomains} disabled={!labDomainOptions.length || labBusy}>
                    {labSelectedDomains.length === labDomainOptions.length ? "Bỏ chọn tất cả" : "Chọn tất cả"}
                  </Button>
                  <Button size="small" onClick={() => setLabSelectedDomains([])} disabled={!labSelectedDomains.length || labBusy}>
                    Bỏ chọn
                  </Button>
                </Stack>
              ) : null}
            </Stack>
            {domainHistoryExpanded ? (
              <Stack spacing={0.25} sx={{ mt: 0.75, maxHeight: 260, overflowY: "auto" }}>
                {labDomainOptions.map((option) => {
                  const { domain } = option;
                  const selected = labSelectedDomains.includes(domain);
                  const isCurrentScan = String(option.scan_id) === String(scan?.id);
                  return (
                    <Stack
                      key={domain}
                      direction="row"
                      spacing={0.75}
                      alignItems="center"
                      sx={{ px: 0.5, borderRadius: 1, cursor: "pointer", bgcolor: selected ? "action.selected" : "transparent", "&:hover": { bgcolor: "action.hover" } }}
                      onClick={() => toggleLabDomain(domain)}
                    >
                      <Checkbox
                        size="small"
                        checked={selected}
                        disabled={labBusy}
                        onClick={(event) => event.stopPropagation()}
                        onChange={() => toggleLabDomain(domain)}
                      />
                      <Typography variant="body2" sx={{ flex: 1 }}>{domain}</Typography>
                      <Chip size="small" label={`${option.hit_count} credential`} variant="outlined" />
                      <Chip size="small" label={isCurrentScan ? "Scan hiện tại" : "Lịch sử"} color={isCurrentScan ? "info" : "default"} variant="outlined" />
                    </Stack>
                  );
                })}
                {!labDomainOptions.length ? (
                  <Typography variant="caption" color="text.secondary">Chưa có domain trong lịch sử scan.</Typography>
                ) : null}
              </Stack>
            ) : null}
          </Paper>
          <Paper
            variant="outlined"
            sx={{ flex: "1 1 100%", p: 1.25, borderRadius: 2, bgcolor: "background.default" }}
          >
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ sm: "center" }} justifyContent="space-between">
              <Box>
                <Typography variant="subtitle2">Proxy login</Typography>
                <Typography variant="caption" color="text.secondary">
                  Chọn một proxy đã lưu bằng dấu tích, hoặc dùng trực tiếp không qua proxy.
                </Typography>
              </Box>
              <Button
                size="small"
                variant={proxyEditorOpen ? "contained" : "outlined"}
                startIcon={<AddCircleOutlineIcon />}
                onClick={() => setProxyEditorOpen((current) => !current)}
                disabled={labBusy || proxyProfileBusy}
              >
                Add proxy
              </Button>
            </Stack>
            <Stack spacing={0.5} sx={{ mt: 1 }}>
              <Stack
                direction="row"
                spacing={0.75}
                alignItems="center"
                sx={{ px: 0.5, py: 0.25, borderRadius: 1, cursor: "pointer", "&:hover": { bgcolor: "action.hover" } }}
                onClick={() => selectLabProxyProfile("")}
              >
                <Checkbox
                  size="small"
                  checked={!labProxyProfileId}
                  disabled={labBusy || proxyProfileBusy}
                  onClick={(event) => event.stopPropagation()}
                  onChange={() => selectLabProxyProfile("")}
                />
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2">Không dùng proxy</Typography>
                  <Typography variant="caption" color="text.secondary">Kết nối trực tiếp từ worker</Typography>
                </Box>
              </Stack>
              {labProxyProfiles.map((profile) => {
                const selected = String(profile.id) === String(labProxyProfileId);
                return (
                  <Stack
                    key={profile.id}
                    direction="row"
                    spacing={0.75}
                    alignItems="center"
                    sx={{ px: 0.5, py: 0.25, borderRadius: 1, cursor: "pointer", bgcolor: selected ? "action.selected" : "transparent", "&:hover": { bgcolor: "action.hover" } }}
                    onClick={() => selectLabProxyProfile(profile.id)}
                  >
                    <Checkbox
                      size="small"
                      checked={selected}
                      disabled={labBusy || proxyProfileBusy}
                      onClick={(event) => event.stopPropagation()}
                      onChange={() => selectLabProxyProfile(profile.id)}
                    />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography variant="body2" noWrap>{profile.name}</Typography>
                        {profile.is_default ? <Chip size="small" label="Mặc định" color="info" variant="outlined" /> : null}
                      </Stack>
                      <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
                        {profile.proxy_display}
                      </Typography>
                    </Box>
                    <IconButton
                      size="small"
                      color={profile.is_default ? "warning" : "default"}
                      title={profile.is_default ? "Proxy mặc định" : "Đặt làm proxy mặc định"}
                      disabled={proxyProfileBusy || labBusy || profile.is_default}
                      onClick={(event) => {
                        event.stopPropagation();
                        setDefaultLabProxyProfile(profile.id);
                      }}
                    >
                      {profile.is_default ? <StarIcon fontSize="small" /> : <StarBorderIcon fontSize="small" />}
                    </IconButton>
                    <IconButton
                      size="small"
                      color="error"
                      title="Xóa proxy đã lưu"
                      disabled={proxyProfileBusy || labBusy}
                      onClick={(event) => {
                        event.stopPropagation();
                        deleteLabProxyProfile(profile.id);
                      }}
                    >
                      <DeleteOutlineIcon fontSize="small" />
                    </IconButton>
                  </Stack>
                );
              })}
              {!labProxyProfiles.length ? (
                <Typography variant="caption" color="text.secondary" sx={{ px: 0.5, py: 0.5 }}>
                  Chưa có proxy đã lưu. Bấm “Add proxy” để thêm.
                </Typography>
              ) : null}
            </Stack>
            {proxyEditorOpen ? (
              <Stack spacing={1} sx={{ mt: 1.25, pt: 1.25, borderTop: 1, borderColor: "divider" }}>
                <Typography variant="caption" color="text.secondary">
                  Nhập URL đầy đủ (ví dụ <code>http://user:pass@host:8080</code>) hoặc dạng <code>host:port</code>. Hỗ trợ HTTP(S), SOCKS4/5.
                </Typography>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Proxy URL hoặc host:port"
                    placeholder="socks5://proxy.lab:1080 hoặc proxy.lab:1080"
                    value={labProxyUrl}
                    onChange={(event) => setLabProxyUrl(event.target.value)}
                    disabled={labBusy || allowlistBusy || proxyProfileBusy}
                  />
                  <TextField
                    fullWidth
                    size="small"
                    label="Tên proxy"
                    placeholder="VPS proxy chính"
                    value={labProxyProfileName}
                    onChange={(event) => setLabProxyProfileName(event.target.value)}
                    disabled={proxyProfileBusy}
                  />
                </Stack>
                <Stack direction={{ xs: "column", md: "row" }} spacing={1} alignItems={{ md: "center" }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Username (nếu URL không có)"
                    value={labProxyUsername}
                    onChange={(event) => setLabProxyUsername(event.target.value)}
                    disabled={!labProxyUrl.trim() || proxyProfileBusy}
                    autoComplete="off"
                  />
                  <TextField
                    fullWidth
                    size="small"
                    type="password"
                    label="Password (nếu URL không có)"
                    value={labProxyPassword}
                    onChange={(event) => setLabProxyPassword(event.target.value)}
                    disabled={!labProxyUrl.trim() || proxyProfileBusy}
                    autoComplete="new-password"
                  />
                  <Button
                    variant="contained"
                    onClick={saveLabProxyProfile}
                    disabled={!labProxyUrl.trim() || !labProxyProfileName.trim() || proxyProfileBusy}
                  >
                    {proxyProfileBusy ? <CircularProgress size={18} /> : "Lưu proxy"}
                  </Button>
                </Stack>
              </Stack>
            ) : null}
          </Paper>
          <Button
            variant="contained"
            color="warning"
            disabled={!selectedIds.size || !labSelectedDomains.length || labBusy || labJobs.some((job) => ACTIVE.has(job.status))}
            onClick={startLabVerification}
          >
            {labBusy || labJobs.some((job) => ACTIVE.has(job.status))
              ? <CircularProgress size={18} color="inherit" />
              : `Verify ${labSelectedDomains.length || "selected"} domain${labSelectedDomains.length === 1 ? "" : "s"}`}
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
              Job #{labJob.id} · {labJob.target_url} · {labJob.proxy_display ? `proxy ${labJob.proxy_display} · ` : "direct · "}{labJob.status} · {labJob.attempt_count || 0} attempt(s) · {labJob.success_count || 0} success(es)
            </Typography>
            {labJobs.length > 1 ? (
              <Stack direction="row" spacing={0.75} flexWrap="wrap" useFlexGap sx={{ mt: 0.75 }}>
                {labJobs.map((job) => (
                  <Chip
                    key={job.id}
                    size="small"
                    label={`${job.target_domain} · ${job.status}`}
                    color={job.status === "completed" && job.success_count ? "success" : ACTIVE.has(job.status) ? "warning" : "default"}
                    variant={job.id === labJob.id ? "filled" : "outlined"}
                    onClick={() => setLabJob(job)}
                  />
                ))}
              </Stack>
            ) : null}
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
              <IconButton
                size="small"
                title={historyExpanded ? "Collapse history" : "Expand history"}
                aria-label={historyExpanded ? "Collapse login attempt history" : "Expand login attempt history"}
                onClick={() => setHistoryExpanded((current) => !current)}
              >
                {historyExpanded ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
              </IconButton>
              <Typography variant="subtitle2">Login attempt history</Typography>
              <Chip size="small" label={String(labHistory.length)} />
            </Stack>
            {historyExpanded ? <Stack direction="row" spacing={1}>
              <Button
                size="small"
                color="error"
                startIcon={<DeleteOutlineIcon />}
                disabled={historyBusy || !labHistory.some((row) => !ACTIVE.has(row.status))}
                onClick={clearLabHistory}
              >
                Clear history
              </Button>
            </Stack> : null}
          </Stack>
          {historyExpanded ? (
            <DataTable
              columns={labHistoryColumns}
              rows={labHistory}
              loading={historyBusy && !labHistory.length}
              empty="No login history yet"
            />
          ) : null}
        </Box>
      </Paper>

    </Box>
  );
}
