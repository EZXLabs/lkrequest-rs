//! Session cookie jar with Chrome's cookie ordering.
//!
//! `cookie_store` keys cookies by domain, path and name in hash maps, so its
//! `matches` order is arbitrary and differs between sessions. Chrome orders
//! the cookies it sends by path length (longest first) and then by creation
//! time (oldest first) — `CookieMonster::CookieSorter` in
//! `net/cookies/cookie_monster.cc`. [`CookieJar`] records a creation sequence
//! for every stored cookie so [`CookieJar::matches`] can reproduce that order.

use std::collections::HashMap;
use std::ops::Deref;

use cookie_store::{Cookie, CookieError, CookieStore, RawCookie, StoreAction};
use url::Url;

/// `(domain, path, name)`, exactly as `cookie_store` keys a stored cookie.
type CookieKey = (String, String, String);

/// Ignore empty Max-Age attributes before cookie 0.18 treats them as overflow.
pub(super) fn parse_set_cookie(header: &str) -> Result<RawCookie<'_>, cookie::ParseError> {
    let mut attributes = header.split(';');
    let cookie_pair = attributes.next().unwrap_or_default();
    let empty_max_age = |attribute: &str| {
        attribute.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("max-age") && value.trim().is_empty()
        })
    };
    if !attributes.clone().any(empty_max_age) {
        return RawCookie::parse(header);
    }

    // Use the parser's attribute boundaries, preserving the cookie pair and
    // every other attribute verbatim, including duplicate ordering.
    let mut normalized = String::with_capacity(header.len());
    normalized.push_str(cookie_pair);
    for attribute in attributes {
        if !empty_max_age(attribute) {
            normalized.push(';');
            normalized.push_str(attribute);
        }
    }
    RawCookie::parse(normalized)
}

fn cookie_key(cookie: &Cookie<'_>) -> CookieKey {
    (
        String::from(&cookie.domain),
        String::from(&cookie.path),
        cookie.name().to_owned(),
    )
}

/// A [`CookieStore`] plus the creation order Chrome sorts by.
///
/// Reads go through [`Deref`] to the store, except [`matches`](Self::matches),
/// which applies Chrome's order. All writes must go through
/// [`insert_raw`](Self::insert_raw) so the creation order stays in step with
/// the store.
#[derive(Debug, Clone, Default)]
pub(crate) struct CookieJar {
    store: CookieStore,
    created: HashMap<CookieKey, u64>,
    next_created: u64,
}

impl CookieJar {
    /// Parse `raw` as received from `request_url` and store it, following the
    /// same RFC 6265 storage rules as [`CookieStore::insert_raw`].
    ///
    /// Like Chrome, overwriting a cookie with the same value keeps its creation
    /// time, while a new value makes it a new cookie that sorts after the
    /// existing ones (`CookieMonster::MaybeDeleteEquivalentCookieAndUpdateStatus`).
    pub(crate) fn insert_raw(
        &mut self,
        raw: &RawCookie<'_>,
        request_url: &Url,
    ) -> Result<StoreAction, CookieError> {
        let cookie = Cookie::try_from_raw_cookie(raw, request_url)?.into_owned();
        let key = cookie_key(&cookie);
        let unchanged_value = self
            .store
            .get(&key.0, &key.1, &key.2)
            .is_some_and(|old| old.value() == cookie.value());

        let result = self.store.insert(cookie, request_url);

        // A rejected insert leaves the store, and so the order, untouched.
        if result.is_ok() {
            if self.store.get(&key.0, &key.1, &key.2).is_none() {
                self.created.remove(&key);
            } else if !(unchanged_value && self.created.contains_key(&key)) {
                self.created.insert(key, self.next_created);
                self.next_created += 1;
            }
        }
        let store = &self.store;
        self.created
            .retain(|(domain, path, name), _| store.get(domain, path, name).is_some());
        result
    }

    /// Cookies to send to `request_url`, in the order Chrome sends them: longer
    /// paths first, then older cookies first.
    pub(crate) fn matches(&self, request_url: &Url) -> Vec<&Cookie<'static>> {
        let mut cookies = self.store.matches(request_url);
        cookies.sort_by_cached_key(|cookie| {
            let path_len = String::from(&cookie.path).len();
            let created = self
                .created
                .get(&cookie_key(cookie))
                .copied()
                .unwrap_or(u64::MAX);
            (std::cmp::Reverse(path_len), created)
        });
        cookies
    }

    /// Every unexpired cookie, oldest first. Storing them into an empty jar in
    /// this order reproduces the creation order, and so the `Cookie` headers
    /// [`matches`](Self::matches) produces.
    pub(crate) fn unexpired_in_creation_order(&self) -> Vec<&Cookie<'static>> {
        let mut cookies: Vec<_> = self.store.iter_unexpired().collect();
        cookies.sort_by_cached_key(|cookie| {
            self.created
                .get(&cookie_key(cookie))
                .copied()
                .unwrap_or(u64::MAX)
        });
        cookies
    }
}

impl Deref for CookieJar {
    type Target = CookieStore;

    fn deref(&self) -> &CookieStore {
        &self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn set(jar: &mut CookieJar, request_url: &str, set_cookie: &str) {
        let raw = RawCookie::parse(set_cookie.to_owned()).unwrap();
        jar.insert_raw(&raw, &url(request_url)).unwrap();
    }

    fn header(jar: &CookieJar, request_url: &str) -> String {
        jar.matches(&url(request_url))
            .iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Golden from Chrome 153.0.8010.47 (headless, fresh profile): the same
    /// `Set-Cookie` sequence, one response each, produced this `Cookie` header
    /// on three separate runs.
    #[test]
    fn matches_the_cookie_header_chrome_sent() {
        let mut jar = CookieJar::default();
        for set_cookie in [
            "b=1; Path=/",
            "a=2; Path=/",
            "api=3; Path=/api",
            "c=4; Path=/",
            "a=2; Path=/; Max-Age=3600",
            "b=changed; Path=/",
        ] {
            set(&mut jar, "http://127.0.0.1:8765/", set_cookie);
        }
        assert_eq!(
            header(&jar, "http://127.0.0.1:8765/api/echo"),
            "api=3; a=2; c=4; b=changed"
        );
    }

    #[test]
    fn same_path_cookies_follow_creation_order() {
        let mut jar = CookieJar::default();
        for (i, name) in ["f", "a", "d", "b", "e", "c"].iter().enumerate() {
            set(
                &mut jar,
                "https://example.com/",
                &format!("{name}={i}; Path=/"),
            );
        }
        assert_eq!(
            header(&jar, "https://example.com/"),
            "f=0; a=1; d=2; b=3; e=4; c=5"
        );
    }

    #[test]
    fn longer_paths_sort_first_regardless_of_creation() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "root=1; Path=/");
        set(&mut jar, "https://example.com/", "deep=2; Path=/api/v1");
        set(&mut jar, "https://example.com/", "mid=3; Path=/api");
        set(&mut jar, "https://example.com/", "root2=4; Path=/");
        assert_eq!(
            header(&jar, "https://example.com/api/v1/users"),
            "deep=2; mid=3; root=1; root2=4"
        );
    }

    #[test]
    fn same_name_at_different_paths_sends_the_longer_path_first() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "token=root; Path=/");
        set(&mut jar, "https://example.com/", "token=api; Path=/api");
        assert_eq!(
            header(&jar, "https://example.com/api/x"),
            "token=api; token=root"
        );
    }

    #[test]
    fn domains_interleave_by_creation_time() {
        let mut jar = CookieJar::default();
        set(
            &mut jar,
            "https://example.com/",
            "x=1; Domain=example.com; Path=/",
        );
        set(&mut jar, "https://a.example.com/", "y=2; Path=/");
        set(
            &mut jar,
            "https://example.com/",
            "z=3; Domain=example.com; Path=/",
        );
        assert_eq!(header(&jar, "https://a.example.com/"), "x=1; y=2; z=3");
    }

    #[test]
    fn overwrite_with_same_value_keeps_creation_time() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "a=1; Path=/");
        set(&mut jar, "https://example.com/", "b=2; Path=/");
        set(
            &mut jar,
            "https://example.com/",
            "a=1; Path=/; Max-Age=3600",
        );
        assert_eq!(header(&jar, "https://example.com/"), "a=1; b=2");
    }

    #[test]
    fn overwrite_with_new_value_is_a_new_cookie() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "a=1; Path=/");
        set(&mut jar, "https://example.com/", "b=2; Path=/");
        set(&mut jar, "https://example.com/", "a=changed; Path=/");
        assert_eq!(header(&jar, "https://example.com/"), "b=2; a=changed");
    }

    #[test]
    fn deleted_then_recreated_cookie_sorts_last() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "a=1; Path=/");
        set(&mut jar, "https://example.com/", "b=2; Path=/");
        set(&mut jar, "https://example.com/", "a=; Path=/; Max-Age=0");
        assert_eq!(header(&jar, "https://example.com/"), "b=2");
        assert!(!jar.created.contains_key(&(
            "example.com".to_owned(),
            "/".to_owned(),
            "a".to_owned()
        )));
        set(&mut jar, "https://example.com/", "a=1; Path=/");
        assert_eq!(header(&jar, "https://example.com/"), "b=2; a=1");
    }

    #[test]
    fn rejected_cookie_leaves_order_untouched() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://example.com/", "a=1; Path=/");
        let foreign = RawCookie::parse("x=1; Domain=other.com").unwrap();
        assert!(jar
            .insert_raw(&foreign, &url("https://example.com/"))
            .is_err());
        assert_eq!(jar.created.len(), 1);
        assert_eq!(header(&jar, "https://example.com/"), "a=1");
    }

    #[test]
    fn unexpired_cookies_list_oldest_first_across_domains_and_paths() {
        let mut jar = CookieJar::default();
        set(&mut jar, "https://b.example.com/", "one=1; Path=/x");
        set(&mut jar, "https://a.example.com/", "two=2; Path=/");
        set(&mut jar, "https://b.example.com/", "three=3; Path=/");
        set(&mut jar, "https://b.example.com/", "one=changed; Path=/x");
        let names: Vec<_> = jar
            .unexpired_in_creation_order()
            .iter()
            .map(|c| c.name().to_owned())
            .collect();
        assert_eq!(names, ["two", "three", "one"]);
    }

    #[test]
    fn order_is_identical_across_jars() {
        let build = || {
            let mut jar = CookieJar::default();
            for (i, name) in ["a", "b", "c", "d", "e", "f"].iter().enumerate() {
                set(
                    &mut jar,
                    "https://example.com/",
                    &format!("{name}={i}; Path=/"),
                );
            }
            header(&jar, "https://example.com/")
        };
        let first = build();
        for _ in 0..20 {
            assert_eq!(build(), first);
        }
    }
}
