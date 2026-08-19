import { createTheme } from "@mui/material/styles";

export const cyberTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#3dffa8", contrastText: "#04120c" },
    secondary: { main: "#7eb6ff" },
    error: { main: "#ff6b7a" },
    warning: { main: "#ffc14d" },
    info: { main: "#7eb6ff" },
    success: { main: "#3dffa8" },
    background: {
      default: "#070b12",
      paper: "#0c1320",
    },
    text: {
      primary: "#e8eef7",
      secondary: "#8b9bb4",
    },
    divider: "rgba(61, 255, 168, 0.14)",
  },
  typography: {
    fontFamily:
      'Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    h1: { fontWeight: 700, letterSpacing: "-0.03em" },
    h2: { fontWeight: 600, letterSpacing: "-0.02em" },
    h3: { fontWeight: 600, letterSpacing: "-0.02em" },
    h4: { fontWeight: 600, letterSpacing: "-0.01em" },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    body1: {
      fontSize: "0.92rem",
      lineHeight: 1.55,
    },
    body2: {
      fontSize: "0.84rem",
      lineHeight: 1.55,
    },
    caption: { letterSpacing: "0.01em" },
    button: { textTransform: "none", fontWeight: 600 },
  },
  shape: { borderRadius: 6 },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundImage:
            "radial-gradient(ellipse 90% 55% at 12% -15%, rgba(61,255,168,0.10), transparent)," +
            "radial-gradient(ellipse 70% 45% at 92% 0%, rgba(126,182,255,0.08), transparent)",
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          backgroundColor: "rgba(7, 11, 18, 0.92)",
          borderBottom: "1px solid rgba(61, 255, 168, 0.12)",
          backdropFilter: "blur(10px)",
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: "#0a101a",
          borderRight: "1px solid rgba(61, 255, 168, 0.1)",
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        head: {
          color: "#8b9bb4",
          fontSize: "0.75rem",
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          borderBottomColor: "rgba(61, 255, 168, 0.12)",
        },
        body: {
          borderBottomColor: "rgba(255,255,255,0.06)",
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        containedPrimary: {
          boxShadow: "none",
          "&:hover": { boxShadow: "0 0 0 1px rgba(61,255,168,0.35)" },
        },
      },
    },
  },
});
