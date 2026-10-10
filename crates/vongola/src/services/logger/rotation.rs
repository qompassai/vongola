// #################################################################
// /qompassai/vongola/crates/vongola/src/services/logger/rotation.rs
// Qompass AI Rotation
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use time::Duration;

use crate::config::LogRotation;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Rotation(pub LogRotation);

impl Rotation {
    /// Provides a daily rotation
    pub const DAILY: Self = Self(LogRotation::Daily);
    /// Provides an hourly rotation
    pub const HOURLY: Self = Self(LogRotation::Hourly);
    /// Provides a minutely rotation
    pub const MINUTELY: Self = Self(LogRotation::Minutely);
    /// Provides a rotation that never rotates.
    pub const NEVER: Self = Self(LogRotation::Never);

    pub(super) fn next_date(
        &self,
        current_date: &time::OffsetDateTime,
    ) -> Option<time::OffsetDateTime> {
        let unrounded_next_date = match *self {
            Rotation::MINUTELY => *current_date + Duration::minutes(1),
            Rotation::HOURLY => *current_date + Duration::hours(1),
            Rotation::DAILY => *current_date + Duration::days(1),
            Rotation::NEVER => return None,
        };
        Some(self.round_date(&unrounded_next_date))
    }

    // note that this method will panic if passed a `Rotation::NEVER`.
    pub(super) fn round_date(&self, date: &time::OffsetDateTime) -> time::OffsetDateTime {
        match *self {
            Rotation::MINUTELY => {
                let time = time::Time::from_hms(date.hour(), date.minute(), 0)
                    .expect("Invalid time; this is a bug");
                date.replace_time(time)
            }
            Rotation::HOURLY => {
                let time =
                    time::Time::from_hms(date.hour(), 0, 0).expect("Invalid time; this is a bug");
                date.replace_time(time)
            }
            Rotation::DAILY => {
                let time = time::Time::from_hms(0, 0, 0).expect("Invalid time; this is a bug");
                date.replace_time(time)
            }
            // Rotation::NEVER is impossible to round.
            Rotation::NEVER => {
                unreachable!("Rotation::NEVER is impossible to round.")
            }
        }
    }

    pub(super) fn date_format(&self) -> Vec<time::format_description::FormatItem<'static>> {
        match *self {
            Rotation::MINUTELY => {
                time::format_description::parse("[year]-[month]-[day]-[hour]-[minute]")
            }
            Rotation::HOURLY => time::format_description::parse("[year]-[month]-[day]-[hour]"),
            Rotation::DAILY => time::format_description::parse("[year]-[month]-[day]"),
            Rotation::NEVER => Result::Ok(vec![]),
        }
        .expect("Unable to create a formatter; this is a bug")
    }
}
