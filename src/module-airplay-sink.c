/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering
  Copyright 2008 Colin Guthrie
  Copyright 2021 Roman Isaev

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pulsecore/core-util.h>
#include <pulsecore/modargs.h>
#include <pulsecore/module.h>
#include <pulsecore/sink.h>

PA_MODULE_AUTHOR("Roman Isaev");
PA_MODULE_DESCRIPTION("Airplay Sink");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(false);
PA_MODULE_USAGE(
    "name=<name of the sink, to be prefixed> "
    "sink_name=<name for the sink> ");

static const char *const valid_modargs[] = {
    "name",
    "sink_name",
    NULL
};

int pa__init(pa_module *m) {
  /* pa_modargs *ma = NULL; */

  /* pa_assert(m); */

  /* pa_modargs_free(ma); */
  pa_log_debug("Loading module module-airplay-sink...");

  return 0;

  /* fail: */

  /*     if (ma) */
  /*         pa_modargs_free(ma); */

  /*     pa__done(m); */

  /*     return -1; */
}

void pa__done(pa_module *m) {}
