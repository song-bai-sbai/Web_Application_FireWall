mod_pwd_waf.la: mod_pwd_waf.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_pwd_waf.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_pwd_waf.la
