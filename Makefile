include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-wifi-monitor
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)
PKG_MAINTAINER:=Catsimple

LUCI_TITLE:=LuCI Support for XIAOMI WR30U WiFi Monitor
LUCI_DEPENDS:=+luci-base +curl +ca-bundle +openssh-client
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
