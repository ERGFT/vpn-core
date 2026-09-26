//! Маршрутизатор: по данным соединения выбирает выход.
//!
//! Сейчас (Фаза 0 плана развития) — только выход по умолчанию (`final`);
//! правила по доменам, адресам и базам стран добавляются в Фазе 1.

use std::collections::HashMap;
use std::sync::Arc;

use super::outbound::Outbound;
use super::Metadata;
use crate::error::{Error, Result};

pub struct Router {
    outbounds: HashMap<String, Arc<dyn Outbound>>,
    final_: Arc<dyn Outbound>,
}

impl Router {
    /// `final_tag` — выход по умолчанию; не задан — первый в списке.
    pub fn new(outbounds: Vec<Arc<dyn Outbound>>, final_tag: Option<&str>) -> Result<Self> {
        let first = outbounds
            .first()
            .cloned()
            .ok_or_else(|| Error::Config("не задан ни один выход (outbound)".into()))?;
        let mut map = HashMap::new();
        for o in outbounds {
            if map.insert(o.tag().to_string(), o.clone()).is_some() {
                return Err(Error::Config(format!(
                    "два выхода с одинаковым tag = \"{}\"",
                    o.tag()
                )));
            }
        }
        let final_ = match final_tag {
            Some(t) => map
                .get(t)
                .cloned()
                .ok_or_else(|| Error::Config(format!("route.final: нет выхода с tag = \"{t}\"")))?,
            None => first,
        };
        Ok(Router {
            outbounds: map,
            final_,
        })
    }

    /// Выход для соединения.
    pub fn select(&self, _meta: &Metadata) -> Arc<dyn Outbound> {
        self.final_.clone()
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag).cloned()
    }
}
