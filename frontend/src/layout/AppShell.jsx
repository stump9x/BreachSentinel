import { useEffect, useState } from "react";
import { Link as RouterLink, Outlet, useLocation, Navigate } from "react-router-dom";
import {
  AppBar,
  Box,
  Button,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { useTheme } from "@mui/material/styles";
import MenuIcon from "@mui/icons-material/Menu";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import CellTowerOutlinedIcon from "@mui/icons-material/CellTowerOutlined";
import WaterDropOutlinedIcon from "@mui/icons-material/WaterDropOutlined";
import TravelExploreOutlinedIcon from "@mui/icons-material/TravelExploreOutlined";
import BoltOutlinedIcon from "@mui/icons-material/BoltOutlined";
import AutoAwesomeOutlinedIcon from "@mui/icons-material/AutoAwesomeOutlined";
import VisibilityOutlinedIcon from "@mui/icons-material/VisibilityOutlined";
import RssFeedOutlinedIcon from "@mui/icons-material/RssFeedOutlined";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import GitHubIcon from "@mui/icons-material/GitHub";
import DocumentScannerOutlinedIcon from "@mui/icons-material/DocumentScannerOutlined";
import { useAuth } from "../auth/AuthContext";
import { loadNavOpenPreference, writeNavOpenPreference } from "./navPreference";

const DRAWER_WIDTH = 232;

const NAV = [
  { to: "/", label: "Overview", icon: <DashboardOutlinedIcon fontSize="small" /> },
  { to: "/indicators", label: "Indicators", icon: <DnsOutlinedIcon fontSize="small" /> },
  { to: "/threats", label: "The Wire", icon: <CellTowerOutlinedIcon fontSize="small" /> },
  { to: "/feeds", label: "RSS Sources", icon: <RssFeedOutlinedIcon fontSize="small" /> },
  { to: "/leaks", label: "Data Leaks", icon: <WaterDropOutlinedIcon fontSize="small" /> },
  { to: "/osint", label: "OSINT Scan", icon: <TravelExploreOutlinedIcon fontSize="small" /> },
  { to: "/logs-scanner", label: "Logs Scanner", icon: <DocumentScannerOutlinedIcon fontSize="small" /> },
  { to: "/github-scanner", label: "GitHub Scanner", icon: <GitHubIcon fontSize="small" /> },
  { to: "/workers", label: "Workers", icon: <BoltOutlinedIcon fontSize="small" /> },
  { to: "/watch-rules", label: "Watch Rules", icon: <VisibilityOutlinedIcon fontSize="small" /> },
  { to: "/intelligence", label: "AI & MISP", icon: <AutoAwesomeOutlinedIcon fontSize="small" /> },
];

export default function AppShell() {
  const { authed, username, logout } = useAuth();
  const location = useLocation();
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down("md"));
  const [navOpen, setNavOpen] = useState(() => loadNavOpenPreference());

  useEffect(() => {
    if (compact) {
      setNavOpen(false);
    } else {
      setNavOpen(loadNavOpenPreference());
    }
  }, [compact]);

  useEffect(() => {
    if (!compact) {
      writeNavOpenPreference(navOpen);
    }
  }, [navOpen, compact]);

  if (!authed) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  const toggleNav = () => setNavOpen((open) => !open);
  const closeNav = () => setNavOpen(false);
  const sidebarVisible = navOpen && !compact;

  const drawer = (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <Box sx={{ px: 2, py: 2.25, display: "flex", alignItems: "center", gap: 1 }}>
        <ShieldOutlinedIcon sx={{ color: "primary.main" }} />
        <Typography variant="h6" sx={{ color: "primary.main", letterSpacing: "-0.02em" }}>
          BreachSentinel
        </Typography>
      </Box>
      <Divider />
      <List sx={{ px: 1, py: 1.5, flex: 1 }}>
        {NAV.map((item) => {
          const selected =
            item.to === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.to);
          return (
            <ListItemButton
              key={item.to}
              component={RouterLink}
              to={item.to}
              selected={selected}
              onClick={() => compact && closeNav()}
              sx={{
                mb: 0.5,
                borderRadius: 1,
                "&.Mui-selected": {
                  bgcolor: "rgba(61, 255, 168, 0.1)",
                  borderLeft: "2px solid",
                  borderColor: "primary.main",
                },
              }}
            >
              <ListItemIcon sx={{ minWidth: 36, color: selected ? "primary.main" : "text.secondary" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText primary={item.label} />
            </ListItemButton>
          );
        })}
      </List>
      <Box sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {username || "analyst"}
        </Typography>
        <Button fullWidth variant="outlined" color="secondary" onClick={logout}>
          Sign out
        </Button>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          zIndex: (t) => t.zIndex.drawer + 1,
          borderBottom: "1px solid",
          borderColor: "divider",
          bgcolor: "background.default",
        }}
      >
        <Toolbar variant="dense" sx={{ minHeight: 48 }}>
          <IconButton
            edge="start"
            color="inherit"
            aria-label={navOpen ? "Hide navigation" : "Show navigation"}
            onClick={toggleNav}
            sx={{ mr: 0.5 }}
          >
            <MenuIcon fontSize="small" />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Drawer
        variant={compact ? "temporary" : "persistent"}
        open={navOpen}
        onClose={closeNav}
        ModalProps={{ keepMounted: true }}
        sx={{
          width: sidebarVisible ? DRAWER_WIDTH : 0,
          flexShrink: 0,
          transition: theme.transitions.create("width", {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          [`& .MuiDrawer-paper`]: {
            width: DRAWER_WIDTH,
            boxSizing: "border-box",
            top: 48,
            height: "calc(100% - 48px)",
            borderRight: "1px solid",
            borderColor: "divider",
            transition: theme.transitions.create("width", {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
            ...(!compact && !navOpen
              ? {
                  width: 0,
                  overflowX: "hidden",
                  borderRight: "none",
                }
              : {}),
          },
        }}
      >
        {drawer}
      </Drawer>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          px: { xs: 2, md: 3 },
          py: 3,
          mt: 6,
          minWidth: 0,
          transition: theme.transitions.create(["width", "margin"], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          width: sidebarVisible ? { md: `calc(100% - ${DRAWER_WIDTH}px)` } : "100%",
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
}
