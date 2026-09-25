//! Замер разовой «прогревочной» стоимости криптографии при первом
//! соединении (найдено в Этапе 8: первое подключение — ~36 мс, все
//! последующие — ~2 мс).
//!
//! Печатает время по шагам: установка crypto-провайдера rustls, сборка
//! провайдера, первая и последующие генерации ключей обмена. Цель —
//! понять, что именно стоит десятки миллисекунд ровно один раз.
//!
//! Запуск: cargo run --release -p bench --bin warmup_probe

use std::time::Instant;

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    // 1. Установка провайдера по умолчанию (это делает
    //    transport::tcp_tls::ensure_crypto_provider при первом вызове).
    let t = Instant::now();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    println!("установка crypto-провайдера:            {:8.2} мс", ms(t));

    // 2. Сборка структуры провайдера (делается на каждое соединение).
    let t = Instant::now();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    println!("сборка CryptoProvider:                  {:8.2} мс", ms(t));

    // 3. Первая генерация ключа обмена — здесь ожидается разовая
    //    инициализация библиотеки (проверка возможностей процессора,
    //    самотесты, засев генератора случайных чисел).
    // Какую группу мерить — из аргумента (по умолчанию та, что реально
    // использует REALITY). Запускать надо в ОТДЕЛЬНЫХ процессах: разовая
    // инициализация на то и разовая, второй замер в том же процессе уже
    // ничего не покажет.
    let want = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "X25519MLKEM768".to_string());
    let group = provider
        .kx_groups
        .iter()
        .find(|g| format!("{:?}", g.name()) == want)
        .unwrap_or_else(|| {
            panic!(
                "группа {want} не найдена; есть: {:?}",
                provider
                    .kx_groups
                    .iter()
                    .map(|g| g.name())
                    .collect::<Vec<_>>()
            )
        });
    println!("группа обмена ключами:                  {:?}", group.name());

    // Если задан аргумент RANDOM_FIRST — сначала берём случайные байты,
    // и только потом генерируем ключ. Так видно, что именно платит
    // разовую цену: засев генератора случайных чисел или сама генерация.
    if std::env::var("RANDOM_FIRST").is_ok() {
        let t = Instant::now();
        let mut b = [0u8; 32];
        provider
            .secure_random
            .fill(&mut b)
            .expect("случайные байты");
        println!("СНАЧАЛА случайные байты:                {:8.2} мс", ms(t));
    }

    let t = Instant::now();
    let kx = group.start().expect("генерация ключа");
    let first = ms(t);
    println!("ПЕРВАЯ генерация ключа:                 {:8.2} мс", first);
    std::hint::black_box(kx.pub_key().len());

    // 4. Последующие — для сравнения.
    let mut total = 0.0;
    let n = 20;
    for _ in 0..n {
        let t = Instant::now();
        let kx = group.start().expect("генерация ключа");
        total += ms(t);
        std::hint::black_box(kx.pub_key().len());
    }
    println!(
        "последующие генерации (среднее из {n}):  {:8.2} мс",
        total / n as f64
    );

    // 5. Случайные байты — тот же генератор, что использует REALITY.
    let t = Instant::now();
    let mut buf = [0u8; 32];
    provider
        .secure_random
        .fill(&mut buf)
        .expect("случайные байты");
    println!("первое получение случайных байт:        {:8.2} мс", ms(t));

    let t = Instant::now();
    for _ in 0..100 {
        provider.secure_random.fill(&mut buf).unwrap();
    }
    println!("100 последующих получений:              {:8.2} мс", ms(t));

    println!();
    println!("Вывод: если ПЕРВАЯ генерация ключа стоит десятки миллисекунд,");
    println!("а последующие — доли, значит это разовая инициализация");
    println!("криптобиблиотеки, и её можно сделать заранее, при старте.");
}
