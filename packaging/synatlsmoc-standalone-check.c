#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <libfprint/fprint.h>

static int
fail_error (const char *operation, GError *error)
{
  fprintf (stderr, "%s: %s\n", operation,
           error != NULL ? error->message : "unknown error");
  g_clear_error (&error);
  return 1;
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree gchar *pairing = NULL;
  gsize pairing_len = 0;
  GPtrArray *devices;
  FpDevice *device = NULL;
  struct stat st;
  int result = 1;

  if (argc != 3)
    {
      fprintf (stderr, "usage: %s PAIRING-DATA STABLE-DEVICE-ID\n", argv[0]);
      return 2;
    }

  if (stat (argv[1], &st) != 0)
    {
      fprintf (stderr, "cannot stat pairing data: %s\n", strerror (errno));
      return 1;
    }
  if (!S_ISREG (st.st_mode) || (st.st_mode & 077) != 0)
    {
      fprintf (stderr, "pairing data must be a regular file with no group/world permissions (mode 0600 recommended)\n");
      return 1;
    }
  if (!g_file_get_contents (argv[1], &pairing, &pairing_len, &error))
    return fail_error ("cannot read pairing data", g_steal_pointer (&error));
  if (pairing_len == 0)
    {
      fprintf (stderr, "pairing data is empty\n");
      return 1;
    }

  context = fp_context_new ();
  fp_context_enumerate (context);
  devices = fp_context_get_devices (context);

  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *candidate = g_ptr_array_index (devices, i);

      if (g_strcmp0 (fp_device_get_driver (candidate), "synatlsmoc") == 0 &&
          g_strcmp0 (fp_device_get_device_id (candidate), argv[2]) == 0)
        {
          if (device != NULL)
            {
              fprintf (stderr, "refusing: multiple matching devices found\n");
              return 1;
            }
          device = candidate;
        }
    }

  if (device == NULL)
    {
      fprintf (stderr, "refusing: exact synatlsmoc device '%s' not found\n", argv[2]);
      return 1;
    }

  if (fp_device_has_feature (device, FP_DEVICE_FEATURE_IDENTIFY) ||
      fp_device_has_feature (device, FP_DEVICE_FEATURE_STORAGE_DELETE) ||
      fp_device_has_feature (device, FP_DEVICE_FEATURE_STORAGE_CLEAR) ||
      fp_device_has_feature (device, FP_DEVICE_FEATURE_UPDATE_PRINT))
    {
      fprintf (stderr, "refusing: driver advertises a prohibited capability\n");
      return 1;
    }
  if (!fp_device_has_feature (device, FP_DEVICE_FEATURE_VERIFY) ||
      !fp_device_has_feature (device, FP_DEVICE_FEATURE_STORAGE_LIST))
    {
      fprintf (stderr, "refusing: driver lacks verify or storage-list capability\n");
      return 1;
    }

  if (!fp_device_set_persistent_data (device, (guchar *) pairing,
                                      pairing_len, &error))
    return fail_error ("pairing data rejected", g_steal_pointer (&error));
  if (!fp_device_open_sync (device, NULL, &error))
    return fail_error ("device open failed", g_steal_pointer (&error));

  {
    g_autoptr(GPtrArray) prints = fp_device_list_prints_sync (device, NULL, &error);

    if (prints == NULL)
      {
        fail_error ("template listing failed", g_steal_pointer (&error));
        goto close_device;
      }

    printf ("SAFE LIBFPRINT CHECK PASSED\n");
    printf ("driver: %s\n", fp_device_get_driver (device));
    printf ("stable device ID: %s\n", fp_device_get_device_id (device));
    printf ("stored template count: %u\n", prints->len);
    result = 0;
  }

close_device:
  if (!fp_device_close_sync (device, NULL, &error))
    {
      fail_error ("ordinary close failed", g_steal_pointer (&error));
      result = 1;
    }

  return result;
}
