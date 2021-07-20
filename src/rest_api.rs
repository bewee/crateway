/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{db::Db, router};
use rocket::{Build, Rocket};

fn rocket() -> Rocket<Build> {
    rocket::build()
        .manage(Db::new())
        .mount("/", router::routes())
}

pub async fn launch() {
    rocket()
        .ignite()
        .await
        .expect("Ignite rocket")
        .launch()
        .await
        .expect("Launch rocket");
}

#[cfg(test)]
mod test {
    extern crate rusty_fork;
    extern crate serial_test;
    use super::*;
    use rocket::{http::Status, local::blocking::Client};
    use rusty_fork::rusty_fork_test;
    use serial_test::serial;
    use std::{env, fs};

    fn setup() {
        let dir = env::temp_dir().join(".webthingsio");
        fs::remove_dir_all(&dir); // We really don't want to handle this result, since we don't care if the directory never existed
        env::set_var("WEBTHINGS_HOME", dir);
    }

    rusty_fork_test! {
        #[test]
        #[serial]
        fn get_things() {
            setup();
            let client = Client::tracked(rocket()).expect("Valid rocket instance");
            let response = client.get("/things").dispatch();
            assert_eq!(response.status(), Status::Ok);
            assert_eq!(response.into_string(), Some("[]".into()));
        }

        #[test]
        #[serial]
        fn get_thing() {
            setup();
            let client = Client::tracked(rocket()).expect("Valid rocket instance");
            let response = client.get("/thing/test").dispatch();
            assert_eq!(response.status(), Status::NotFound);
        }
    }
}