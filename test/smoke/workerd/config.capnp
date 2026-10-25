# workerd config for the smoke run. worker.bundle.mjs is built from worker.mjs; see the comment at
# the top of that file for the commands.
#
# compatibilityDate is the date the pinned workerd release supports. workerd refuses a newer one,
# so bump it with the workerd version in package.json, never ahead of it. From 2026-08-04 the
# nodejs_compat flags are on by default; they are switched off here so the run proves the library
# needs nothing from Node.

using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .smokeWorker),
  ],
);

const smokeWorker :Workerd.Worker = (
  modules = [
    (name = "worker", esModule = embed "worker.bundle.mjs"),
  ],
  compatibilityDate = "2026-10-25",
  compatibilityFlags = ["no_nodejs_compat", "no_nodejs_compat_v2"],
);
