import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Button,
  Chip,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { api } from "../api/client";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { StatusChip } from "../components/StatusChips";

const STATUS_LABELS = {
  ok: "Thành công",
  success: "Thành công",
  completed: "Hoàn tất",
  running: "Đang chạy",
  queued: "Đang chờ",
  pending: "Chờ xử lý",
  skipped: "Bỏ qua",
  partial: "Một phần",
  failed: "Thất bại",
  error: "Lỗi",
};

const DIRECTION_LABELS = {
  export: "Xuất sang MISP",
  import: "Nhập từ MISP",
  both: "Hai chiều",
};

function VietnameseStatusChip({ value }) {
  const key = String(value || "").toLowerCase();
  return <StatusChip value={value} label={STATUS_LABELS[key] || value || "—"} />;
}

export default function IntelligencePage() {
  const [briefings, setBriefings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [misp, setMisp] = useState(null);
  const [health, setHealth] = useState(null);
  const [nerText, setNerText] = useState("");
  const [nerResult, setNerResult] = useState(null);
  const [latestBriefing, setLatestBriefing] = useState(null);
  const [keyword, setKeyword] = useState("ransomware");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [b, l, m, h] = await Promise.all([
        api.get("/api/v1/ai/briefings/?page_size=10"),
        api.get("/api/v1/integrations/logs/?page_size=10"),
        api.get("/api/v1/misp/status/"),
        api.get("/api/v1/integrations/health/"),
      ]);
      setBriefings(b.results || []);
      setLogs(l.results || []);
      setMisp(m);
      setHealth(h);
    } catch (err) {
      setError(err.message || "Không thể tải bảng tình báo");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function generateBriefing() {
    setBusy("briefing");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/ai/briefings/generate/", {
        window_hours: 24,
        async_mode: false,
      });
      setLatestBriefing(data);
      setMsg(`Đã tạo bản tóm tắt bằng ${data.provider || "AI"}`);
      await load();
    } catch (err) {
      setError(err.message || "Không thể tạo bản tóm tắt");
    } finally {
      setBusy("");
    }
  }

  async function runNer() {
    setBusy("ner");
    setError("");
    try {
      const data = await api.post("/api/v1/ai/extract-entities/", {
        text: nerText,
        persist: true,
      });
      setNerResult(data);
      setMsg(`Đã trích xuất thực thể · lưu mới ${data.persisted_created ?? 0}`);
    } catch (err) {
      setError(err.message || "Không thể trích xuất thực thể");
    } finally {
      setBusy("");
    }
  }

  async function syncMisp(direction) {
    setBusy("misp");
    setError("");
    setMsg("");
    try {
      const data = await api.post("/api/v1/misp/sync/", {
        direction,
        limit: 50,
        async_mode: false,
      });
      const statusLabel = { ok: "thành công", success: "thành công", skipped: "bỏ qua", error: "lỗi" };
      const statuses = (data.results || [])
        .map((r) => statusLabel[r.status] || r.status)
        .join(", ");
      setMsg(`MISP — ${direction === "export" ? "xuất" : direction === "import" ? "nhập" : "đồng bộ hai chiều"}: ${statuses}`);
      await load();
    } catch (err) {
      setError(err.message || "Không thể đồng bộ MISP");
    } finally {
      setBusy("");
    }
  }

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Tóm tắt AI"
        action={
          <Button variant="outlined" onClick={load}>
            Làm mới
          </Button>
        }
      />
      {error ? <Alert severity="error">{error}</Alert> : null}
      {msg ? <Alert severity="success">{msg}</Alert> : null}

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        <Chip
          size="small"
          variant="outlined"
          color={health?.ai?.anthropic_configured ? "success" : "default"}
          label={`Anthropic: ${health?.ai?.anthropic_configured ? "bật" : "tắt"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={health?.ai?.huggingface_configured ? "success" : "default"}
          label={`HuggingFace: ${health?.ai?.huggingface_configured ? "bật" : "tắt"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={misp?.configured ? "success" : "default"}
          label={`MISP: ${misp?.configured ? "đã cấu hình" : "chưa cấu hình"}`}
        />
        <Chip
          size="small"
          variant="outlined"
          color={health?.searxng_configured ? "success" : "default"}
          label={`SearxNG: ${health?.searxng_configured ? "bật" : "tắt"}`}
        />
      </Stack>

      <Typography variant="h6">Bản tóm tắt AI</Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button
          variant="contained"
          onClick={generateBriefing}
          disabled={Boolean(busy)}
        >
          {busy === "briefing" ? "Đang tạo…" : "Tạo bản tóm tắt 24 giờ"}
        </Button>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={async () => {
            setBusy("weekly");
            setError("");
            try {
              const data = await api.post("/api/v1/ai/weekly-digest/", {});
              setLatestBriefing(data);
              setMsg("Đã tạo bản tóm tắt top 5 trong tuần");
              await load();
            } catch (err) {
              setError(err.message || "Không thể tạo tóm tắt tuần");
            } finally {
              setBusy("");
            }
          }}
        >
          Tóm tắt top 5 tuần
        </Button>
      </Stack>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} alignItems="flex-start">
        <TextField
          label="Tóm tắt theo từ khóa"
          placeholder="lockbit / CVE-2024 / tên miền"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          sx={{ minWidth: 280, flex: 1 }}
        />
        <Button
          variant="outlined"
          color="secondary"
          disabled={Boolean(busy) || !keyword.trim()}
          onClick={async () => {
            setBusy("keyword");
            setError("");
            try {
              const data = await api.post("/api/v1/ai/keyword-summary/", {
                keyword: keyword.trim(),
                window_hours: 168,
              });
              setLatestBriefing(data);
              setMsg(`Đã tóm tắt từ khóa "${keyword.trim()}"`);
              await load();
            } catch (err) {
              setError(err.message || "Không thể tóm tắt từ khóa");
            } finally {
              setBusy("");
            }
          }}
        >
          Tóm tắt
        </Button>
      </Stack>
      {latestBriefing?.content ? (
        <TextField
          label="Bản tóm tắt mới nhất"
          value={latestBriefing.content}
          multiline
          minRows={8}
          fullWidth
          InputProps={{ readOnly: true }}
        />
      ) : null}

      <Typography variant="h6">Trích xuất thực thể</Typography>
      <TextField
        label="Văn bản tình báo"
        value={nerText}
        onChange={(e) => setNerText(e.target.value)}
        multiline
        minRows={4}
        fullWidth
      />
      <Button
        variant="outlined"
        onClick={runNer}
        disabled={Boolean(busy) || !nerText.trim()}
        sx={{ alignSelf: "flex-start" }}
      >
        {busy === "ner" ? "Đang trích xuất…" : "Trích xuất và lưu IOC"}
      </Button>
      {nerResult ? (
        <Typography variant="body2" color="text.secondary" component="pre" sx={{ whiteSpace: "pre-wrap" }}>
          {JSON.stringify(nerResult.entities, null, 2)}
        </Typography>
      ) : null}

      <Typography variant="h6">Đồng bộ MISP</Typography>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
        <Button
          variant="outlined"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("export")}
        >
          Xuất IOC → MISP
        </Button>
        <Button
          variant="outlined"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("import")}
        >
          Nhập MISP → IOC
        </Button>
        <Button
          variant="contained"
          color="secondary"
          disabled={Boolean(busy)}
          onClick={() => syncMisp("both")}
        >
          Đồng bộ hai chiều
        </Button>
      </Stack>
      {!misp?.configured ? (
        <Typography variant="body2" color="text.secondary">
          Thêm MISP_URL và MISP_API_KEY vào `.env` để bật đồng bộ. Khi chưa cấu hình, tác vụ sẽ
          được bỏ qua.
        </Typography>
      ) : null}

      <Typography variant="h6">Bản tóm tắt gần đây</Typography>
      <DataTable
        rows={briefings}
        columns={[
          { id: "title", label: "Tiêu đề" },
          { id: "provider", label: "Nhà cung cấp" },
          {
            id: "status",
            label: "Trạng thái",
            render: (row) => <VietnameseStatusChip value={row.status} />,
          },
          {
            id: "counts",
            label: "Số liệu",
            render: (row) =>
              `Tin: ${row.threat_count} · IOC: ${row.indicator_count} · Rò rỉ: ${row.leak_count}`,
          },
          {
            id: "created_at",
            label: "Thời gian tạo",
            render: (row) =>
              row.created_at ? new Date(row.created_at).toLocaleString() : "—",
          },
        ]}
      />

      <Typography variant="h6">Nhật ký tích hợp</Typography>
      <DataTable
        rows={logs}
        columns={[
          { id: "target", label: "Đích" },
          {
            id: "direction",
            label: "Chiều đồng bộ",
            render: (row) => DIRECTION_LABELS[row.direction] || row.direction || "—",
          },
          {
            id: "status",
            label: "Trạng thái",
            render: (row) => <VietnameseStatusChip value={row.status} />,
          },
          { id: "message", label: "Thông báo" },
          { id: "records_processed", label: "Số bản ghi" },
        ]}
      />
    </Stack>
  );
}
