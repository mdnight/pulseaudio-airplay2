/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering
  Copyright 2008 Colin Guthrie
  Copyright 2021 Roman Isaev

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/alternative.h>
#include <avahi-common/domain.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>

#include <pulse/xmalloc.h>


#include <pulsecore/avahi-wrap.h>
#include <pulsecore/core-util.h>
#include <pulsecore/hashmap.h>
#include <pulsecore/log.h>
#include <pulsecore/modargs.h>
#include <pulsecore/namereg.h>

PA_MODULE_AUTHOR("Roman Isaev");
PA_MODULE_DESCRIPTION("mDNS/DNS-SD Service Discovery of Airplay devices");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);
PA_MODULE_USAGE("latency_msec=<audio latency - applies to all devices> ");

#define SERVICE_TYPE_SINK "_airplay._tcp"
#define FEATURE_SUPPORTS_AIRPLAY_AUDIO 9
#define MAC_ADDRESS_MAX_LEN 17

static uint64_t parse_device_id(uint64_t *id, const char *id_str);
static uint64_t parse_device_features(uint64_t *result, const char *features);
static int has_feature(uint64_t features, uint64_t type);
static void resolver_cb(AvahiServiceResolver *r, AvahiIfIndex interface,
                        AvahiProtocol protocol, AvahiResolverEvent event,
                        const char *name, const char *type, const char *domain,
                        const char *host_name, const AvahiAddress *a,
                        uint16_t port, AvahiStringList *txt,
                        AvahiLookupResultFlags flags, void *userdata);
static void client_callback(AvahiClient *c, AvahiClientState state,
                            void *userdata);
static void browser_cb(AvahiServiceBrowser *b, AvahiIfIndex interface,
                       AvahiProtocol protocol, AvahiBrowserEvent event,
                       const char *name, const char *type, const char *domain,
                       AvahiLookupResultFlags flags, void *userdata);
static struct tunnel *tunnel_new(AvahiIfIndex interface, AvahiProtocol protocol,
                                 const char *name, const char *type,
                                 const char *domain);
static void tunnel_free(struct tunnel *t);
static int tunnel_compare(const void *a, const void *b);
static unsigned tunnel_hash(const void *p);

struct userdata {
  pa_core *core;
  pa_module *module;

  AvahiPoll *avahi_poll;
  AvahiClient *client;
  AvahiServiceBrowser *sink_browser;

  pa_hashmap *tunnels;

  uint32_t latency;
  bool latency_set;
};

struct tunnel {
  AvahiIfIndex interface;
  AvahiProtocol protocol;
  char *name, *type, *domain;
  uint32_t module_index;
};

static const char *const valid_modargs[] = {"latency_msec", NULL};

int pa__init(pa_module *m) {
  struct userdata *u;
  pa_modargs *ma = NULL;
  int error;

  if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
    pa_log("Failed to parse module arguments.");
    goto fail;
  }

  m->userdata = u = pa_xnew0(struct userdata, 1);
  u->core = m->core;
  u->module = m;

  if (pa_modargs_get_value(ma, "latency_msec", NULL) != NULL) {
    u->latency_set = true;
    if (pa_modargs_get_value_u32(ma, "latency_msec", &u->latency) < 0) {
      pa_log("Failed to parse latency_msec argument.");
      goto fail;
    }
  }

  u->tunnels = pa_hashmap_new(tunnel_hash, tunnel_compare);

  u->avahi_poll = pa_avahi_poll_new(m->core->mainloop);

  if (!(u->client = avahi_client_new(u->avahi_poll, AVAHI_CLIENT_NO_FAIL,
                                     client_callback, u, &error))) {
    pa_log("pa_avahi_client_new() failed: %s", avahi_strerror(error));
    goto fail;
  }

  pa_modargs_free(ma);

  pa_log_info("module is initialized successfully");

  return 0;

fail:
  pa__done(m);

  if (ma)
    pa_modargs_free(ma);

  pa_log_info("module initialization failed");

  return -1;
}

void pa__done(pa_module *m) {
  struct userdata *u;

  pa_assert(m);

  if (!(u = m->userdata))
    return;

  if (u->client)
    avahi_client_free(u->client);

  if (u->avahi_poll)
    pa_avahi_poll_free(u->avahi_poll);

  pa_xfree(u);

  pa_log_info("module has been unloaded.");
}

static void client_callback(AvahiClient *c, AvahiClientState state,
                            void *userdata) {
  struct userdata *u = userdata;

  pa_assert(c);
  pa_assert(u);

  u->client = c;

  switch (state) {
  case AVAHI_CLIENT_S_REGISTERING:
  case AVAHI_CLIENT_S_RUNNING:
  case AVAHI_CLIENT_S_COLLISION:
    if (!u->sink_browser) {
      if (!(u->sink_browser = avahi_service_browser_new(
                c, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, SERVICE_TYPE_SINK, NULL,
                0, browser_cb, u))) {
        pa_log("avahi_service_browser_new() failed: %s",
               avahi_strerror(avahi_client_errno(c)));
        pa_module_unload_request(u->module, true);
      }
    }

    break;

  case AVAHI_CLIENT_FAILURE:
    if (avahi_client_errno(c) == AVAHI_ERR_DISCONNECTED) {
      int error;

      pa_log_debug("Avahi daemon disconnected.");

      /* Try to reconnect. Very dodgy if-block. Still don't get what happens
       * when we have 1000s tries. */
      if (!(u->client = avahi_client_new(u->avahi_poll, AVAHI_CLIENT_NO_FAIL,
                                         client_callback, u, &error))) {
        pa_log("avahi_client_new() failed: %s", avahi_strerror(error));
        pa_module_unload_request(u->module, true);
      }
    }

  case AVAHI_CLIENT_CONNECTING:
    if (u->sink_browser) {
      avahi_service_browser_free(u->sink_browser);
      u->sink_browser = NULL;
    }

    break;

  default:
    break;
  }
}

static void browser_cb(AvahiServiceBrowser *b, AvahiIfIndex interface,
                       AvahiProtocol protocol, AvahiBrowserEvent event,
                       const char *name, const char *type, const char *domain,
                       AvahiLookupResultFlags flags, void *userdata) {

  struct userdata *u = userdata;
  struct tunnel *t;

  pa_assert(u);

  if (flags & AVAHI_LOOKUP_RESULT_LOCAL) {
    pa_log_debug("AVAHI_LOOKUP_RESULT_LOCAL is true");
    return;
  }

  t = tunnel_new(interface, protocol, name, type, domain);

  if (event == AVAHI_BROWSER_NEW) {
    pa_log_debug("AVAHI_BROWSER_NEW event");
    if (!pa_hashmap_get(u->tunnels, t))
      if (!(avahi_service_resolver_new(u->client, interface, protocol, name,
                                       type, domain, AVAHI_PROTO_UNSPEC, 0,
                                       resolver_cb, u)))
        pa_log("avahi_service_resolver_new() failed: %s",
               avahi_strerror(avahi_client_errno(u->client)));
  } else if (event == AVAHI_BROWSER_REMOVE) {
    pa_log_debug("AVAHI_BROWSER_REMOVE) event");
    struct tunnel *t2;
    if ((t2 = pa_hashmap_get(u->tunnels, t))) {
      pa_module_unload_request_by_index(u->core, t2->module_index, true);
      pa_hashmap_remove(u->tunnels, t2);
      tunnel_free(t2);
    }
  }

  tunnel_free(t);
}

static void resolver_cb(AvahiServiceResolver *r, AvahiIfIndex interface,
                        AvahiProtocol protocol, AvahiResolverEvent event,
                        const char *name, const char *type, const char *domain,
                        const char *host_name, const AvahiAddress *a,
                        uint16_t port, AvahiStringList *txt,
                        AvahiLookupResultFlags flags, void *userdata) {

  struct userdata *u = userdata;
  pa_module *m;
  uint64_t ret;
  AvahiStringList *l;

  uint64_t *id = NULL;
  uint64_t features = 0;
  char *txt_device_id = NULL;
  char *txt_features = NULL;
  char at[AVAHI_ADDRESS_STR_MAX];
  struct tunnel *tnl;
  char *args;

  pa_log_debug("In resolver_cb...");

  pa_assert(u);

  tnl = tunnel_new(interface, protocol, name, type, domain);

  if (event != AVAHI_RESOLVER_FOUND) {
    pa_log("Resolving of '%s' failed: %s", name,
           avahi_strerror(avahi_client_errno(u->client)));
    goto resolver_cb_finish;
  }

  char *key, *value;
  for (l = txt; l; l = l->next) {
    pa_assert_se(avahi_string_list_get_pair(l, &key, &value, NULL) == 0);

    pa_log_debug("Found key: '%s' with value: '%s'", key, value);

    if (pa_streq(key, "deviceid")) {
      pa_xfree(txt_device_id);
      txt_device_id = pa_xstrdup(value);
      ret = parse_device_id(id, txt_device_id);

      if (ret < 0) {
        pa_log("Could not extract AirPlay device ID ('%s'): %s", name,
               txt_device_id);
        goto resolver_cb_failure;
      }
    } else if (pa_streq(key, "features")) {
      if (NULL == value) {
        pa_log("Device '%s' is not Airplay2 device", name);
        goto resolver_cb_failure;
      }
      pa_xfree(txt_features);
      txt_features = pa_xstrdup(value);

      if (parse_device_features(&features, txt_features) != 0) {
        pa_log("Device %s: error occured during features conversion", name);
        goto resolver_cb_failure;
      }

      if (!has_feature(features, FEATURE_SUPPORTS_AIRPLAY_AUDIO)) {
        pa_log("Device %s doesn't support audio", name);
        goto resolver_cb_failure;
      }
    } else if (pa_streq(key, "model")) {
      if (strncmp(value, "AudioAccessory", strlen("AudioAccessory")) != 0) {
        pa_log("Device %s is not a HOMEPOD. Give me a HOMEPOD, bitch!", name);
        goto resolver_cb_failure;
      }
    }

    avahi_free(key);
    avahi_free(value);
  }

  avahi_address_snprint(at, sizeof(at), a);

  args = pa_sprintf_malloc("server=[%s]:%u "
                           "sink_name=%s "
                           "device.model=\"%s\"' ",
                           at, port, name, "HomePod");

  pa_log_debug("Loading module-raop-sink with arguments '%s'", args);

  if (pa_module_load(&m, u->core, "module-airplay-sink", args) >= 0) {
    tnl->module_index = m->index;
    pa_hashmap_put(u->tunnels, tnl, tnl);
    tnl = NULL;
  }

  goto resolver_cb_finish;

resolver_cb_failure:
  avahi_free(key);
  avahi_free(value);

resolver_cb_finish:
  avahi_service_resolver_free(r);

  if (tnl)
    tunnel_free(tnl);
}

static struct tunnel *tunnel_new(AvahiIfIndex interface, AvahiProtocol protocol,
                                 const char *name, const char *type,
                                 const char *domain) {
  struct tunnel *t;

  t = pa_xnew(struct tunnel, 1);
  t->interface = interface;
  t->protocol = protocol;
  t->name = pa_xstrdup(name);
  t->type = pa_xstrdup(type);
  t->domain = pa_xstrdup(domain);
  t->module_index = PA_IDXSET_INVALID;

  return t;
}

static void tunnel_free(struct tunnel *t) {
  pa_assert(t);
  pa_xfree(t->name);
  pa_xfree(t->type);
  pa_xfree(t->domain);
  pa_xfree(t);
}

static int tunnel_compare(const void *a, const void *b) {
  const struct tunnel *ta = a, *tb = b;
  int r;

  if (ta->interface != tb->interface)
    return 1;
  if (ta->protocol != tb->protocol)
    return 1;
  if ((r = strcmp(ta->name, tb->name)))
    return r;
  if ((r = strcmp(ta->type, tb->type)))
    return r;
  if ((r = strcmp(ta->domain, tb->domain)))
    return r;

  return 0;
}

static unsigned tunnel_hash(const void *p) {
  const struct tunnel *t = p;

  return (unsigned)t->interface + (unsigned)t->protocol +
         pa_idxset_string_hash_func(t->name) +
         pa_idxset_string_hash_func(t->type) +
         pa_idxset_string_hash_func(t->domain);
}

static uint64_t parse_device_id(uint64_t *id, const char *id_str) {
  int i;
  char *s;
  char *ptr;
  uint64_t result;
  int ret = -1;

  s = pa_xmalloc(MAC_ADDRESS_MAX_LEN + 1);
  ptr = s;
  for (i = 0; i < MAC_ADDRESS_MAX_LEN; i++) {
    if (!isxdigit(*id_str)) {
      id_str++;
      continue;
    }

    *ptr = *id_str;

    id_str++;
    ptr++;
  }
  *ptr = '\0';

  result = (uint64_t)strtoull(s, NULL, 16);

  if (errno == 0) {
    ret = 0;
    *id = result;
  }

  pa_xfree(s);
  return ret;
}

static uint64_t parse_device_features(uint64_t *result, const char *features) {
  char *ptr = NULL;

  errno = 0;
  uint64_t part_little = (uint64_t)strtoul(features, &ptr, 16);
  if (errno != 0) {
    goto parse_device_features_fail;
  }
  pa_log_debug("parse_device_features -> part_little: %ld ", part_little);

  uint64_t part_big = (uint64_t)strtoul(ptr + 1, NULL, 16);
  if (errno != 0) {
    goto parse_device_features_fail;
  }
  part_big = part_big << 32;
  pa_log_debug("parse_device_features -> part_big: %ld ", part_big);

  *result = part_big + part_little;

  return 0;

parse_device_features_fail:
  return errno;
}

static int has_feature(uint64_t features, uint64_t type) {
  return features & (1 << type);
}
