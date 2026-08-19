import { Avatar, Chip, Stack } from "@mui/material";
import {
  formatWebsiteTag,
  geographyFlagUrl,
  geographyTagLabel,
  orderedWireTags,
} from "../utils/wireTags";

function GeographyFlagAvatar({ src }) {
  return (
    <Avatar
      alt=""
      src={src}
      variant="square"
      imgProps={{ loading: "lazy", referrerPolicy: "no-referrer" }}
      sx={{
        width: 18,
        height: 13,
        borderRadius: "2px",
        bgcolor: "transparent",
        "& img": { objectFit: "cover", width: 18, height: 13 },
      }}
    />
  );
}

/** Website / KEV / topic / geography chips for a Wire row (shared by table + cards). */
export function WireTagChips({ row, maxTags = 5 }) {
  const displayTags = orderedWireTags(row, maxTags);
  if (!displayTags.length) return null;

  return (
    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
      {displayTags.map((item) => {
        if (item.kind === "kev") {
          return (
            <Chip
              key={item.key}
              size="small"
              color="error"
              label="KEV"
              variant="outlined"
            />
          );
        }
        const tag = item.tag;
        const key = tag.id || tag.slug || tag.name;
        if (item.kind === "geography") {
          const flagSrc = geographyFlagUrl(tag, 20);
          return (
            <Chip
              key={key}
              size="small"
              avatar={flagSrc ? <GeographyFlagAvatar src={flagSrc} /> : undefined}
              label={geographyTagLabel(tag)}
              variant="outlined"
              color="warning"
            />
          );
        }
        return (
          <Chip
            key={key}
            size="small"
            label={item.kind === "website" ? formatWebsiteTag(tag) : tag.slug || tag.name}
            variant={item.kind === "website" ? "filled" : "outlined"}
            color={item.kind === "website" ? "info" : "default"}
          />
        );
      })}
    </Stack>
  );
}
