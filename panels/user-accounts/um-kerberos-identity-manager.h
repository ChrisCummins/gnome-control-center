/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Authors: Ray Strode
 */

#ifndef __UM_KERBEROS_IDENTITY_MANAGER_H__
#define __UM_KERBEROS_IDENTITY_MANAGER_H__

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "um-identity-manager.h"

G_BEGIN_DECLS

#define UM_TYPE_KERBEROS_IDENTITY_MANAGER           (um_kerberos_identity_manager_get_type ())
#define UM_KERBEROS_IDENTITY_MANAGER(obj)           (G_TYPE_CHECK_INSTANCE_CAST (obj, UM_TYPE_KERBEROS_IDENTITY_MANAGER, UmKerberosIdentityManager))
#define UM_KERBEROS_IDENTITY_MANAGER_CLASS(cls)     (G_TYPE_CHECK_CLASS_CAST (cls, UM_TYPE_KERBEROS_IDENTITY_MANAGER, UmKerberosIdentityManagerClass))
#define UM_IS_KERBEROS_IDENTITY_MANAGER(obj)        (G_TYPE_CHECK_INSTANCE_TYPE (obj, UM_TYPE_KERBEROS_IDENTITY_MANAGER))
#define UM_IS_KERBEROS_IDENTITY_MANAGER_CLASS(obj)  (G_TYPE_CHECK_CLASS_TYPE (obj, UM_TYPE_KERBEROS_IDENTITY_MANAGER))
#define UM_KERBEROS_IDENTITY_MANAGER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), UM_TYPE_KERBEROS_IDENTITY_MANAGER, UmKerberosIdentityManagerClass))

typedef struct _UmKerberosIdentityManager           UmKerberosIdentityManager;
typedef struct _UmKerberosIdentityManagerClass      UmKerberosIdentityManagerClass;
typedef struct _UmKerberosIdentityManagerPrivate    UmKerberosIdentityManagerPrivate; struct _UmKerberosIdentityManager
{
  GObject parent_instance;
  UmKerberosIdentityManagerPrivate *priv;
};

struct _UmKerberosIdentityManagerClass
{
  GObjectClass parent_class;
};

GType                   um_kerberos_identity_manager_get_type  (void);
UmIdentityManager*      um_kerberos_identity_manager_new       (void);
G_END_DECLS

#endif /* __UM_KERBEROS_IDENTITY_MANAGER_H__ */
