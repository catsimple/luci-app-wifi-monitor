include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-wifi-monitor
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)-$(PKG_RELEASE)
PKG_MAINTAINER:=Catsimple

LUCI_TITLE:=LuCI Support for XIAOMI WR30U WiFi Monitor
LUCI_DEPENDS:=+luci-base +curl +ca-bundle +openssh-client +nlbwmon
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	chmod +x /usr/libexec/wifi/api_wifi_acl
	chmod +x /usr/libexec/wifi/api_wifi_json
	chmod +x /usr/libexec/wifi/api_wifi_router
	chmod +x /usr/libexec/wifi/get_vendor
fi
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
