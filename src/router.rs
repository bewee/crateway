/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub(crate) mod addons_router;
pub(crate) mod extensions_router;
pub(crate) mod login_router;
pub(crate) mod ping_router;
pub(crate) mod settings_router;
pub(crate) mod things_router;
pub(crate) mod users_router;

use rocket::{Build, Rocket};

pub fn mount(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket
        .mount("/addons/", addons_router::routes())
        .mount("/extensions/", extensions_router::routes())
        .mount("/login/", login_router::routes())
        .mount("/ping/", ping_router::routes())
        .mount("/settings/", settings_router::routes())
        .mount("/things/", things_router::routes())
        .mount("/users/", users_router::routes())
}
