import { Box, Chip, Paper, Stack, Typography } from "@mui/material";
import PublicOutlinedIcon from "@mui/icons-material/PublicOutlined";
import CalendarMonthOutlinedIcon from "@mui/icons-material/CalendarMonthOutlined";
import { ExternalTitleLink, resolveThreatHref } from "./ExternalTitleLink";
import { WireTagChips } from "./WireTagChips";
import { formatWireDateWithRelative } from "../utils/dateTime";
import { displayThreatTitle } from "../utils/threatTitle";
import { wireFeedName } from "../utils/wireCard";
import {
  geographyFlagUrl,
  geographyTagLabel,
  isGeographyTag,
  preferCountryGeography,
} from "../utils/wireTags";

function HeaderFlags({ row }) {
  const geography = preferCountryGeography(
    (Array.isArray(row?.tags) ? row.tags : []).filter(isGeographyTag)
  )
    .map((tag) => ({ tag, src: geographyFlagUrl(tag, 40) }))
    .filter((item) => item.src)
    .slice(0, 2);
  if (!geography.length) return null;

  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      {geography.map(({ tag, src }) => (
        <Box
          key={tag.id || tag.slug || tag.name}
          component="img"
          src={src}
          alt={geographyTagLabel(tag)}
          title={geographyTagLabel(tag)}
          loading="lazy"
          referrerPolicy="no-referrer"
          sx={{
            width: 22,
            height: 15,
            objectFit: "cover",
            borderRadius: "2px",
            border: "1px solid",
            borderColor: "divider",
          }}
        />
      ))}
    </Stack>
  );
}

export function WireCard({ row, number }) {
  const feed = wireFeedName(row);
  const title = displayThreatTitle(row);

  return (
    <Paper
      elevation={0}
      sx={{
        p: 1.5,
        height: "100%",
        display: "flex",
        flexDirection: "column",
        gap: 1,
        border: "1px solid",
        borderColor: "divider",
        bgcolor: "background.paper",
        transition: "border-color 120ms ease",
        "&:hover": { borderColor: "secondary.main" },
      }}
    >
      <Stack direction="row" spacing={1} alignItems="center">
        <Chip
          size="small"
          color="info"
          label="WIRE"
          sx={{ fontWeight: 700, letterSpacing: "0.08em" }}
        />
        {Number.isFinite(number) && number > 0 ? (
          <Typography variant="caption" color="text.secondary">
            #{number}
          </Typography>
        ) : null}
        <Box sx={{ flexGrow: 1 }} />
        <HeaderFlags row={row} />
      </Stack>

      <Box
        sx={{
          display: "-webkit-box",
          WebkitBoxOrient: "vertical",
          WebkitLineClamp: 3,
          overflow: "hidden",
        }}
      >
        <ExternalTitleLink title={title} href={resolveThreatHref(row)} />
      </Box>

      <Stack spacing={0.5} sx={{ mt: "auto" }}>
        <Stack direction="row" spacing={0.75} alignItems="center">
          <PublicOutlinedIcon sx={{ fontSize: 14, color: "text.secondary" }} />
          <Typography variant="caption" color="text.secondary" noWrap>
            Source: {feed || "—"}
          </Typography>
        </Stack>
        <Stack direction="row" spacing={0.75} alignItems="center">
          <CalendarMonthOutlinedIcon sx={{ fontSize: 14, color: "text.secondary" }} />
          <Typography
            variant="caption"
            color="text.secondary"
            title={`Published ${row.published_at || "—"} · On Wire ${row.created_at || "—"}`}
          >
            {formatWireDateWithRelative(row)}
          </Typography>
        </Stack>
      </Stack>

      <WireTagChips row={row} maxTags={5} />
    </Paper>
  );
}
