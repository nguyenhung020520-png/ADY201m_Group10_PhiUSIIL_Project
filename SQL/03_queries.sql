-- ADY201m, đồ án One-Line Rule: 19 truy vấn của notebook "3. Data Analysis with SQL".
-- Chạy trên Outputs/phishing.duckdb bằng DuckDB 1.0 trở lên (dùng ROLLUP, FILTER, QUALIFY, UNPIVOT, QUANTILE_CONT, regexp_extract).
-- Bảng raw_urls là tệp gốc, bảng urls là phishing_model_table.parquet của Bước 2, bảng tld_codes là tld_country_codes.csv.

-- sql_01_overview: Tổng quan bảng urls theo lớp, kèm một dòng tổng
SELECT CASE WHEN GROUPING(phishing) = 1 THEN 'all' WHEN phishing = 1 THEN 'phishing' ELSE 'legitimate' END AS lop,
       COUNT(*)                     AS so_dia_chi,
       COUNT(DISTINCT URL)          AS so_url_khac_nhau,
       COUNT(DISTINCT Domain)       AS so_ten_mien,
       COUNT(DISTINCT reg_domain)   AS so_ten_mien_dang_ky,
       COUNT(DISTINCT tld_clean)    AS so_tld,
       ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM urls), 2)  AS ty_trong_pct
FROM urls
GROUP BY ROLLUP (phishing)
ORDER BY GROUPING(phishing), phishing;

-- sql_02_duplicates: Địa chỉ xuất hiện hơn một lần trong tệp gốc, theo lớp
WITH dup AS (
    SELECT URL,
           COUNT(*)                   AS so_lan,
           COUNT(DISTINCT phishing)   AS so_nhan,
           MIN(phishing)              AS nhan,
           MAX(URLLength) - MIN(URLLength) AS lech_URLLength
    FROM raw_urls
    GROUP BY URL
    HAVING COUNT(*) > 1
)
SELECT CASE nhan WHEN 1 THEN 'phishing' ELSE 'legitimate' END AS lop,
       COUNT(*)                         AS so_url_trung,
       SUM(so_lan)                      AS so_dong,
       SUM(so_lan - 1)                  AS so_dong_bi_bo,
       SUM(CASE WHEN so_nhan > 1 THEN 1 ELSE 0 END) AS url_mang_hai_nhan,
       SUM(CASE WHEN lech_URLLength = 1 THEN 1 ELSE 0 END) AS cap_lech_URLLength_1
FROM dup
GROUP BY lop;

-- sql_03_two_classes: Hai lớp đặt cạnh nhau: dạng địa chỉ, chỉ số tương đồng và nội dung trang
SELECT CASE phishing WHEN 1 THEN 'phishing' ELSE 'legitimate' END       AS lop,
       COUNT(*)                                                         AS so_dia_chi,
       ROUND(100.0 * AVG(starts_https_www), 2)                          AS bat_dau_https_www_pct,
       ROUND(100.0 * AVG(IsHTTPS), 2)                                   AS https_pct,
       ROUND(100.0 * AVG(has_path), 2)                                  AS co_duong_dan_pct,
       MEDIAN(url_length_true)                                          AS do_dai_that_trung_vi,
       ROUND(AVG(URLSimilarityIndex), 2)                                AS chi_so_tuong_dong_tb,
       ROUND(100.0 * AVG(CASE WHEN URLSimilarityIndex = 100 THEN 1 ELSE 0 END), 2) AS chi_so_bang_100_pct,
       MEDIAN(LineOfCode)                                               AS dong_ma_trung_vi,
       ROUND(100.0 * AVG(CASE WHEN NoOfImage = 0 THEN 1 ELSE 0 END), 1)  AS khong_anh_pct
FROM urls
GROUP BY phishing
ORDER BY phishing;

-- sql_04_prefix_shapes: Bốn dạng tiền tố của địa chỉ, đếm theo lớp
WITH shaped AS (
    SELECT phishing,
           CASE WHEN URL LIKE 'https://www.%' THEN '1 https://www.'
                WHEN URL LIKE 'https://%'     THEN '2 https:// (no www)'
                WHEN URL LIKE 'http://www.%'  THEN '3 http://www.'
                ELSE                               '4 http:// (no www)' END AS tien_to
    FROM urls
)
SELECT tien_to,
       COUNT(*) FILTER (WHERE phishing = 0)                                  AS legitimate,
       COUNT(*) FILTER (WHERE phishing = 1)                                  AS phishing,
       ROUND(100.0 * COUNT(*) FILTER (WHERE phishing = 1) / COUNT(*), 2)     AS lua_dao_pct
FROM shaped
GROUP BY tien_to
ORDER BY tien_to;

-- sql_05_one_line_rules: Bốn quy tắc viết tay trên toàn bộ 235.370 địa chỉ: độ chính xác, tỷ lệ bắt được và báo động giả
WITH flags AS (
    SELECT phishing,
           CASE WHEN URLSimilarityIndex < 100 THEN 1 ELSE 0 END                AS r_similarity,
           1 - starts_https_www                                                AS r_prefix,
           has_path                                                            AS r_path,
           CASE WHEN starts_https_www = 0 OR has_path = 1 THEN 1 ELSE 0 END    AS r_prefix_or_path
    FROM urls
),
long AS (
    SELECT '1 similarity index < 100' AS quy_tac, phishing, r_similarity AS flag FROM flags
    UNION ALL SELECT '2 not https://www.',          phishing, r_prefix         FROM flags
    UNION ALL SELECT '3 has a path',                phishing, r_path           FROM flags
    UNION ALL SELECT '4 not https://www. or path',  phishing, r_prefix_or_path FROM flags
)
SELECT quy_tac,
       ROUND(100.0 * AVG(CASE WHEN flag = phishing THEN 1 ELSE 0 END), 2)  AS do_chinh_xac_pct,
       ROUND(100.0 * AVG(flag) FILTER (WHERE phishing = 1), 2)             AS bat_duoc_pct,
       ROUND(100.0 * AVG(flag) FILTER (WHERE phishing = 0), 2)             AS bao_dong_gia_pct,
       SUM(flag) FILTER (WHERE phishing = 0)                               AS so_dia_chi_hop_le_bi_chan
FROM long
GROUP BY quy_tac
ORDER BY quy_tac;

-- sql_06_similarity_bands: Chỉ số tương đồng theo khoảng 10 điểm: số địa chỉ, tỷ lệ lừa đảo và phần trăm tích luỹ
SELECT LEAST(CAST(FLOOR(URLSimilarityIndex / 10) * 10 AS INTEGER), 100)            AS tu_diem,
       COUNT(*)                                                                    AS so_dia_chi,
       COUNT(*) FILTER (WHERE phishing = 0)                                        AS hop_le,
       ROUND(100.0 * AVG(phishing), 2)                                             AS lua_dao_pct,
       ROUND(100.0 * SUM(COUNT(*)) OVER (ORDER BY tu_diem) / SUM(COUNT(*)) OVER (), 2) AS tich_luy_pct
FROM urls
GROUP BY tu_diem
ORDER BY tu_diem;

-- sql_07_tld_rank: Mười lăm TLD đông nhất: xếp hạng theo số địa chỉ, tỷ trọng và tỷ lệ lừa đảo
WITH by_tld AS (
    SELECT tld_clean,
           COUNT(*)                          AS so_dia_chi,
           ROUND(100.0 * AVG(phishing), 1)   AS lua_dao_pct,
           ROUND(100.0 * AVG(homepage_only), 1) AS trang_chu_pct
    FROM urls
    GROUP BY tld_clean
)
SELECT RANK() OVER (ORDER BY so_dia_chi DESC)                                  AS hang,
       tld_clean, so_dia_chi,
       ROUND(100.0 * so_dia_chi / SUM(so_dia_chi) OVER (), 2)                  AS ty_trong_pct,
       ROUND(100.0 * SUM(so_dia_chi) OVER (ORDER BY so_dia_chi DESC) / SUM(so_dia_chi) OVER (), 1) AS tich_luy_pct,
       lua_dao_pct, trang_chu_pct
FROM by_tld
QUALIFY hang <= 15
ORDER BY hang;

-- sql_08_tld_type: Ba loại TLD (chung, mã nước, địa chỉ IP) ghép với bảng mã nước
SELECT u.tld_type                                             AS loai_tld,
       COUNT(*)                                               AS so_dia_chi,
       COUNT(DISTINCT u.tld_clean)                            AS so_tld,
       COUNT(DISTINCT c.country)                              AS so_nuoc,
       ROUND(100.0 * AVG(u.phishing), 2)                      AS lua_dao_pct,
       ROUND(100.0 * AVG(u.homepage_only), 1)                 AS trang_chu_pct
FROM urls u
LEFT JOIN tld_codes c ON c.code = u.tld_clean
GROUP BY u.tld_type
ORDER BY so_dia_chi DESC;

-- sql_09_countries: Địa lý theo TLD mã nước: các nước có từ 500 địa chỉ, xếp hạng theo tỷ lệ lừa đảo
WITH by_country AS (
    SELECT c.country, u.tld_clean,
           COUNT(*)                          AS so_dia_chi,
           ROUND(100.0 * AVG(u.phishing), 1) AS lua_dao_pct
    FROM urls u
    JOIN tld_codes c ON c.code = u.tld_clean
    GROUP BY c.country, u.tld_clean
    HAVING COUNT(*) >= 500
)
SELECT DENSE_RANK() OVER (ORDER BY lua_dao_pct DESC)  AS hang_lua_dao,
       country, tld_clean, so_dia_chi, lua_dao_pct,
       NTILE(3) OVER (ORDER BY lua_dao_pct DESC)      AS nhom_ba
FROM by_country
ORDER BY hang_lua_dao, so_dia_chi DESC;

-- sql_10_registered_domains: Độ tập trung của địa chỉ lừa đảo theo tên miền đăng ký: hai mươi tên miền đông nhất
WITH by_domain AS (
    SELECT reg_domain,
           COUNT(*)                            AS so_dia_chi,
           SUM(phishing)                       AS lua_dao,
           COUNT(*) - SUM(phishing)            AS hop_le
    FROM urls
    GROUP BY reg_domain
)
SELECT ROW_NUMBER() OVER (ORDER BY lua_dao DESC, reg_domain)                       AS hang,
       reg_domain, so_dia_chi, lua_dao, hop_le,
       ROUND(100.0 * SUM(lua_dao) OVER (ORDER BY lua_dao DESC, reg_domain) / (SELECT SUM(phishing) FROM urls), 2) AS tich_luy_lua_dao_pct
FROM by_domain
QUALIFY hang <= 20
ORDER BY hang;

-- sql_11_length_bands: Phân bố độ dài địa chỉ sau khi cắt tiền tố (pb_length) theo khoảng, tỷ lệ trong từng lớp
WITH banded AS (
    SELECT phishing,
           CASE WHEN pb_length < 10 THEN '1 under 10'
                WHEN pb_length < 15 THEN '2 10-14'
                WHEN pb_length < 20 THEN '3 15-19'
                WHEN pb_length < 30 THEN '4 20-29'
                WHEN pb_length < 50 THEN '5 30-49'
                WHEN pb_length < 100 THEN '6 50-99'
                ELSE '7 100 or more' END AS khoang_do_dai
    FROM urls
)
SELECT khoang_do_dai,
       COUNT(*) FILTER (WHERE phishing = 0)                                                     AS hop_le,
       COUNT(*) FILTER (WHERE phishing = 1)                                                     AS lua_dao,
       ROUND(100.0 * COUNT(*) FILTER (WHERE phishing = 0) / SUM(COUNT(*) FILTER (WHERE phishing = 0)) OVER (), 2) AS hop_le_pct,
       ROUND(100.0 * COUNT(*) FILTER (WHERE phishing = 1) / SUM(COUNT(*) FILTER (WHERE phishing = 1)) OVER (), 2) AS lua_dao_pct
FROM banded
GROUP BY khoang_do_dai
ORDER BY khoang_do_dai;

-- sql_12_length_quantiles: Phân vị của pb_length theo lớp, trên toàn bộ và riêng các địa chỉ là trang chủ
SELECT CASE WHEN homepage_only = 1 THEN 'homepage only' ELSE 'has a path' END AS nhom,
       CASE phishing WHEN 1 THEN 'phishing' ELSE 'legitimate' END AS lop,
       COUNT(*)                              AS so_dia_chi,
       QUANTILE_CONT(pb_length, 0.05)        AS p05,
       QUANTILE_CONT(pb_length, 0.25)        AS p25,
       QUANTILE_CONT(pb_length, 0.50)        AS p50,
       QUANTILE_CONT(pb_length, 0.75)        AS p75,
       QUANTILE_CONT(pb_length, 0.95)        AS p95,
       MAX(pb_length)                        AS lon_nhat
FROM urls
GROUP BY ALL
ORDER BY nhom DESC, lop;

-- sql_13_empty_pages: Trang gần như trống và ô mật khẩu, theo lớp
SELECT CASE phishing WHEN 1 THEN 'phishing' ELSE 'legitimate' END                    AS lop,
       ROUND(100.0 * AVG(CASE WHEN NoOfImage = 0 THEN 1 ELSE 0 END), 1)               AS khong_anh_pct,
       ROUND(100.0 * AVG(CASE WHEN NoOfJS = 0 THEN 1 ELSE 0 END), 1)                  AS khong_js_pct,
       ROUND(100.0 * AVG(CASE WHEN NoOfCSS = 0 THEN 1 ELSE 0 END), 1)                 AS khong_css_pct,
       ROUND(100.0 * AVG(CASE WHEN NoOfImage = 0 AND NoOfJS = 0 AND NoOfCSS = 0 THEN 1 ELSE 0 END), 1) AS ca_ba_bang_0_pct,
       ROUND(100.0 * AVG(CASE WHEN LineOfCode < 50 THEN 1 ELSE 0 END), 1)             AS duoi_50_dong_ma_pct,
       ROUND(100.0 * AVG(HasPasswordField), 1)                                        AS co_o_mat_khau_pct,
       ROUND(100.0 * AVG(HasSubmitButton), 1)                                         AS co_nut_gui_pct
FROM urls
GROUP BY phishing
ORDER BY phishing;

-- sql_14_length_gap: URLLength trừ độ dài thật của chuỗi URL, theo lớp và theo tiền tố tên tệp
SELECT CASE phishing WHEN 1 THEN 'phishing' ELSE 'legitimate' END                 AS lop,
       source_prefix                                                               AS tien_to_ten_tep,
       COUNT(*)                                                                    AS so_dia_chi,
       COUNT(*) FILTER (WHERE URLLength - LENGTH(URL) = -1)                        AS lech_tru_1,
       COUNT(*) FILTER (WHERE URLLength - LENGTH(URL) = 0)                         AS lech_0,
       COUNT(*) FILTER (WHERE URLLength - LENGTH(URL) NOT IN (-1, 0))              AS lech_khac,
       ROUND(100.0 * COUNT(*) FILTER (WHERE URLLength - LENGTH(URL) = -1) / COUNT(*), 1) AS lech_tru_1_pct
FROM urls
GROUP BY ALL
ORDER BY lop, so_dia_chi DESC;

-- sql_15_split_domain_overlap: Địa chỉ kiểm thử có tên miền đăng ký đã gặp trong tập huấn luyện, hai cách chia, năm seed
WITH roles AS (
    UNPIVOT (SELECT row_id, reg_domain, phishing, split_s0, split_s1, split_s2, split_s3, split_s4,
                    gsplit_s0, gsplit_s1, gsplit_s2, gsplit_s3, gsplit_s4 FROM urls)
    ON split_s0, split_s1, split_s2, split_s3, split_s4, gsplit_s0, gsplit_s1, gsplit_s2, gsplit_s3, gsplit_s4
    INTO NAME cach_chia VALUE tap
),
train_domains AS (
    SELECT DISTINCT cach_chia, reg_domain FROM roles WHERE tap = 'train'
)
SELECT CASE WHEN r.cach_chia LIKE 'g%' THEN 'domain split' ELSE 'stratified' END   AS loai_chia,
       r.cach_chia,
       COUNT(*)                                                                    AS dia_chi_kiem_thu,
       ROUND(100.0 * AVG(r.phishing), 2)                                           AS lua_dao_pct,
       ROUND(100.0 * AVG(CASE WHEN t.reg_domain IS NOT NULL THEN 1 ELSE 0 END), 2) AS ten_mien_da_gap_pct,
       ROUND(100.0 * AVG(CASE WHEN t.reg_domain IS NOT NULL THEN 1 ELSE 0 END) FILTER (WHERE r.phishing = 1), 2) AS ten_mien_da_gap_lua_dao_pct
FROM roles r
LEFT JOIN train_domains t ON t.cach_chia = r.cach_chia AND t.reg_domain = r.reg_domain
WHERE r.tap = 'test'
GROUP BY ALL
ORDER BY loai_chia DESC, r.cach_chia;

-- sql_16_tld_seen_unseen: Hai phần của phép thử TLD chưa thấy: kích thước, tỷ lệ lừa đảo, dạng tiền tố và trang chủ
SELECT CASE tld_seen WHEN 1 THEN 'seen (com, org, net)' ELSE 'unseen (other TLDs)' END   AS phan,
       COUNT(*)                                                     AS so_dia_chi,
       COUNT(DISTINCT tld_clean)                                    AS so_tld,
       ROUND(100.0 * AVG(phishing), 2)                              AS lua_dao_pct,
       ROUND(100.0 * AVG(homepage_only), 1)                         AS trang_chu_pct,
       ROUND(100.0 * AVG(starts_https_www) FILTER (WHERE phishing = 1), 2) AS lua_dao_bat_dau_https_www_pct,
       ROUND(100.0 * AVG(IsHTTPS) FILTER (WHERE phishing = 1), 1)   AS lua_dao_https_pct,
       ROUND(AVG(pb_length) FILTER (WHERE phishing = 0), 1)         AS do_dai_tb_hop_le,
       ROUND(AVG(pb_length) FILTER (WHERE phishing = 1), 1)         AS do_dai_tb_lua_dao
FROM urls
GROUP BY tld_seen
ORDER BY tld_seen DESC;

-- sql_17_rq1_homepage_classes: Câu hỏi 1: hai lớp khác nhau thế nào khi chỉ xét các địa chỉ là trang chủ
SELECT CASE phishing WHEN 1 THEN 'phishing' ELSE 'legitimate' END                  AS lop,
       COUNT(*)                                                                    AS so_dia_chi,
       ROUND(100.0 * AVG(starts_https_www), 2)                                     AS bat_dau_https_www_pct,
       ROUND(100.0 * AVG(IsHTTPS), 2)                                              AS https_pct,
       ROUND(100.0 * AVG(CASE WHEN URLSimilarityIndex = 100 THEN 1 ELSE 0 END), 2) AS chi_so_bang_100_pct,
       MEDIAN(pb_length)                                                           AS do_dai_trung_vi,
       ROUND(AVG(pb_digits), 2)                                                    AS chu_so_tb,
       ROUND(100.0 * AVG(CASE WHEN pb_digits > 0 THEN 1 ELSE 0 END), 1)            AS co_chu_so_pct,
       ROUND(100.0 * AVG(CASE WHEN pb_hyphens > 0 THEN 1 ELSE 0 END), 1)           AS co_gach_ngang_pct,
       ROUND(100.0 * AVG(CASE WHEN tld_type = 'country code' THEN 1 ELSE 0 END), 1) AS tld_ma_nuoc_pct
FROM urls
WHERE homepage_only = 1
GROUP BY phishing
ORDER BY phishing;

-- sql_18_rq2_rule_by_seed: Câu hỏi 2: mốc không cần huấn luyện, quy tắc tiền tố trên tập kiểm thử của năm seed phân tầng
WITH roles AS (
    UNPIVOT (SELECT phishing, starts_https_www, has_path, split_s0, split_s1, split_s2, split_s3, split_s4 FROM urls)
    ON split_s0, split_s1, split_s2, split_s3, split_s4
    INTO NAME seed VALUE tap
),
scored AS (
    SELECT seed, phishing,
           1 - starts_https_www                                              AS r_prefix,
           CASE WHEN starts_https_www = 0 OR has_path = 1 THEN 1 ELSE 0 END  AS r_prefix_or_path
    FROM roles
    WHERE tap = 'test'
),
per_seed AS (
    SELECT seed, COUNT(*) AS dia_chi_kiem_thu,
           100.0 * AVG(CASE WHEN r_prefix = phishing THEN 1 ELSE 0 END)          AS acc_prefix,
           100.0 * AVG(r_prefix) FILTER (WHERE phishing = 1)                     AS caught_prefix,
           100.0 * AVG(r_prefix) FILTER (WHERE phishing = 0)                     AS fa_prefix,
           100.0 * AVG(CASE WHEN r_prefix_or_path = phishing THEN 1 ELSE 0 END)  AS acc_both,
           100.0 * AVG(r_prefix_or_path) FILTER (WHERE phishing = 1)             AS caught_both
    FROM scored
    GROUP BY seed
)
SELECT * FROM (
SELECT seed, dia_chi_kiem_thu,
       ROUND(acc_prefix, 2) AS do_chinh_xac_tien_to_pct, ROUND(caught_prefix, 2) AS bat_duoc_tien_to_pct, ROUND(fa_prefix, 2) AS bao_dong_gia_pct,
       ROUND(acc_both, 2) AS do_chinh_xac_tien_to_hoac_duong_dan_pct, ROUND(caught_both, 2) AS bat_duoc_tien_to_hoac_duong_dan_pct
FROM per_seed
UNION ALL
SELECT 'mean', ROUND(AVG(dia_chi_kiem_thu)),
       ROUND(AVG(acc_prefix), 2), ROUND(AVG(caught_prefix), 2), ROUND(AVG(fa_prefix), 2), ROUND(AVG(acc_both), 2), ROUND(AVG(caught_both), 2)
FROM per_seed
UNION ALL
SELECT 'sd', NULL, ROUND(STDDEV_SAMP(acc_prefix), 3), ROUND(STDDEV_SAMP(caught_prefix), 3), ROUND(STDDEV_SAMP(fa_prefix), 3), ROUND(STDDEV_SAMP(acc_both), 3), ROUND(STDDEV_SAMP(caught_both), 3)
FROM per_seed
)
ORDER BY CASE seed WHEN 'mean' THEN 2 WHEN 'sd' THEN 3 ELSE 1 END, seed;

-- sql_19_rq3_rules_by_group: Câu hỏi 3: quy tắc viết tay và chỉ số tương đồng trong các nhóm khó
WITH grouped AS (
    SELECT 'A all addresses' AS nhom, * FROM urls
    UNION ALL SELECT 'B homepage only', * FROM urls WHERE homepage_only = 1
    UNION ALL SELECT 'C unseen TLDs', * FROM urls WHERE tld_seen = 0
    UNION ALL SELECT 'D homepage only, unseen TLDs', * FROM urls WHERE homepage_only = 1 AND tld_seen = 0
    UNION ALL SELECT 'E domain split test, seed 0', * FROM urls WHERE gsplit_s0 = 'test'
)
SELECT nhom,
       COUNT(*)                                                                                   AS so_dia_chi,
       ROUND(100.0 * AVG(phishing), 1)                                                            AS lua_dao_pct,
       ROUND(100.0 * AVG(1 - starts_https_www) FILTER (WHERE phishing = 1), 2)                   AS tien_to_bat_duoc_pct,
       ROUND(100.0 * AVG(1 - starts_https_www) FILTER (WHERE phishing = 0), 2)                   AS tien_to_bao_dong_gia_pct,
       ROUND(100.0 * AVG(1 - IsHTTPS) FILTER (WHERE phishing = 1), 2)                            AS khong_https_bat_duoc_pct,
       ROUND(100.0 * AVG(CASE WHEN URLSimilarityIndex < 100 THEN 1 ELSE 0 END) FILTER (WHERE phishing = 1), 2) AS chi_so_bat_duoc_pct,
       ROUND(100.0 * AVG(CASE WHEN URLSimilarityIndex < 100 THEN 1 ELSE 0 END) FILTER (WHERE phishing = 0), 2) AS chi_so_bao_dong_gia_pct
FROM grouped
GROUP BY nhom
ORDER BY nhom;
