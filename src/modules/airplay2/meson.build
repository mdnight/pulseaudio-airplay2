libairplay_sources = [
]

libairplay_headers = [
]

# FIXME: meson doesn't support multiple RPATH arguments currently
rpath_dirs = join_paths(privlibdir) + ':' + join_paths(modlibexecdir)

libairplay2 = shared_library('airplay2',
  libariplay_sources,
  libairplay_headers,
  c_args : [pa_c_args, server_c_args],
  link_args : [nodelete_link_args],
  include_directories : [configinc, topinc],
  dependencies : [libpulse_dep, libpulsecommon_dep, libpulsecore_dep, librtp_dep, libm_dep, openssl_dep, libintl_dep],
  install : true,
  install_rpath : rpath_dirs,
  install_dir : modlibexecdir,
)
