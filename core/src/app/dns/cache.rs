//! Кеш ответов DNS: ключ — имя и тип запроса, срок — наименьший TTL в
//! ответе (для пустых ответов и NXDOMAIN — из SOA, но не дольше
//! [`NEGATIVE_MAX`]). Размер ограничен: при переполнении сначала уходят
//! просроченные, потом самые старые записи.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};

/// Потолок на срок хранения любого ответа.
pub const MAX_TTL: u32 = 3600;
/// Потолок для отрицательных ответов (нет такого имени / нет записей).
pub const NEGATIVE_MAX: u32 = 60;

type Key = (String, RecordType);
/// Порядок записи: ключ и время, чтобы вытеснять самые старые.
type Order = VecDeque<(Key, Instant)>;

struct Entry {
    msg: Message,
    stored: Instant,
    ttl: u32,
}

pub struct Cache {
    cap: usize,
    inner: Mutex<(HashMap<Key, Entry>, Order)>,
}

/// Срок жизни ответа в кеше; `None` — не кешировать (ошибка сервера).
pub fn cache_ttl(msg: &Message) -> Option<u32> {
    match msg.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        _ => return None,
    }
    if msg.metadata.truncation {
        return None;
    }
    if msg.answers.is_empty() {
        let soa = msg
            .authorities
            .iter()
            .find_map(|r| match &r.data {
                RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                _ => None,
            })
            .unwrap_or(NEGATIVE_MAX);
        return Some(soa.min(NEGATIVE_MAX));
    }
    Some(
        msg.answers
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(0)
            .min(MAX_TTL),
    )
}

impl Cache {
    pub fn new(cap: usize) -> Self {
        Cache {
            cap: cap.max(1),
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    /// Ответ из кеша с уменьшенными на прошедшее время TTL.
    pub fn get(&self, name: &str, qtype: RecordType) -> Option<Message> {
        let key = (name.to_ascii_lowercase(), qtype);
        let mut g = self.inner.lock().unwrap();
        let e = g.0.get(&key)?;
        let age = e.stored.elapsed().as_secs() as u32;
        if age >= e.ttl {
            g.0.remove(&key);
            return None;
        }
        let mut msg = e.msg.clone();
        for r in msg
            .answers
            .iter_mut()
            .chain(msg.authorities.iter_mut())
            .chain(msg.additionals.iter_mut())
        {
            r.ttl = r.ttl.saturating_sub(age).max(1);
        }
        Some(msg)
    }

    pub fn put(&self, name: &str, qtype: RecordType, msg: &Message) {
        let Some(ttl) = cache_ttl(msg) else { return };
        if ttl == 0 {
            return;
        }
        let key = (name.to_ascii_lowercase(), qtype);
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let (map, order) = &mut *g;
        if map.len() >= self.cap && !map.contains_key(&key) {
            // Просроченные — первыми.
            map.retain(|_, e| e.stored.elapsed() < Duration::from_secs(e.ttl as u64));
            // Всё ещё полно — самые старые по времени записи.
            while map.len() >= self.cap {
                match order.pop_front() {
                    Some((k, at)) => {
                        if map.get(&k).is_some_and(|e| e.stored == at) {
                            map.remove(&k);
                        }
                    }
                    None => break,
                }
            }
        }
        // Очередь порядка не должна расти без предела из-за перезаписей.
        if order.len() > self.cap * 4 {
            order.retain(|(k, at)| map.get(k).is_some_and(|e| e.stored == *at));
        }
        order.push_back((key.clone(), now));
        map.insert(
            key,
            Entry {
                msg: msg.clone(),
                stored: now,
                ttl,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record};

    fn answer(ttl: u32, rcode: ResponseCode) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.metadata.response_code = rcode;
        if rcode == ResponseCode::NoError {
            m.add_answer(Record::from_rdata(
                Name::from_ascii("a.test.").unwrap(),
                ttl,
                RData::A(A::new(1, 2, 3, 4)),
            ));
        }
        m
    }

    #[test]
    fn ttl_rules() {
        assert_eq!(cache_ttl(&answer(300, ResponseCode::NoError)), Some(300));
        assert_eq!(
            cache_ttl(&answer(999_999, ResponseCode::NoError)),
            Some(MAX_TTL)
        );
        assert_eq!(
            cache_ttl(&answer(0, ResponseCode::NXDomain)),
            Some(NEGATIVE_MAX)
        );
        assert_eq!(cache_ttl(&answer(10, ResponseCode::ServFail)), None);
    }

    #[test]
    fn get_put_and_bounded_size() {
        let c = Cache::new(3);
        c.put("A.test", RecordType::A, &answer(300, ResponseCode::NoError));
        assert!(c.get("a.test", RecordType::A).is_some(), "регистр не важен");
        assert!(c.get("a.test", RecordType::AAAA).is_none());
        for i in 0..10 {
            c.put(
                &format!("h{i}.test"),
                RecordType::A,
                &answer(300, ResponseCode::NoError),
            );
            assert!(c.len() <= 3);
        }
        assert!(c.get("h9.test", RecordType::A).is_some(), "свежие остаются");
        assert!(c.get("a.test", RecordType::A).is_none(), "старые вытеснены");
        c.put(
            "zero.test",
            RecordType::A,
            &answer(0, ResponseCode::NoError),
        );
        assert!(
            c.get("zero.test", RecordType::A).is_none(),
            "TTL 0 не кешируется"
        );
    }
}
