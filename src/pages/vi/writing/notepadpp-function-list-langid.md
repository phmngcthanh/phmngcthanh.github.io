---
layout: ../../../layouts/ArticleLayout.astro
lang: vi
title: "Function List của Notepad++ và giới hạn trên bị thiếu đối với langID"
description: "Một giá trị cấu hình XML đã dẫn đến phép gán con trỏ sở hữu ngoài biên như thế nào, các phép thử sát biên xác lập được gì, và giới hạn về mô hình đe dọa trong advisory đã công bố."
published: "2026-10-10"
category: "Nghiên cứu bảo mật"
tags:
  - notepadpp
  - memory-safety
  - configuration
draft: false
---

Notepad++ dùng cấu hình Function List để chọn bộ phân tích sẽ trích xuất danh sách hàm trong tài liệu. Ở phiên bản 8.9.8, một số nguyên trong cấu hình đó còn có thể chọn vị trí nằm ngoài bảng bộ phân tích. Khi người dùng mở bảng Function List, chương trình thực hiện phép gán con trỏ sở hữu ngoài biên và, với một số giá trị đã thử, tiến trình trình soạn thảo bị kết thúc.

Dự án công bố phát hiện này dưới mã [GHSA-9rr8-6vjg-gj52](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9rr8-6vjg-gj52) ngày 24 tháng 9 năm 2026, ghi công `phmngcthanh`. Đánh giá công khai là Moderate, CVSS 3.1 **5.5**, đồng thời nêu rõ không khẳng định khả năng thực thi mã. Bài viết giải thích đường xử lý cấu hình và các thử nghiệm làm cơ sở cho báo cáo.

## Đường xử lý cấu hình

Function List liên kết các định danh ngôn ngữ với định nghĩa bộ phân tích. Đầu vào liên quan là `functionList/overrideMap.xml`; mỗi bản ghi liên kết chứa một `id` và, với liên kết cho ngôn ngữ tích hợp sẵn, một giá trị số `langID`.

Cấu hình phải được đặt tại vị trí mà trình soạn thảo thực sự nạp. Chỉ mở một tài liệu XML bất kỳ trong tab không đi qua bộ phân tích này. Các thử nghiệm được ghi lại dùng những bản portable riêng để thử nghiệm, không có plugin, trên Windows 10 x64; cấu hình nằm cạnh Notepad++ 8.9.8.0. Bản cài đặt thông thường có thể nạp thư mục Function List của người dùng trước, rồi dùng thư mục cài đặt làm nơi dự phòng.

Yêu cầu về vị trí tệp rất quan trọng. Một hồ sơ hoặc gói cấu hình do đối phương cung cấp là một mô hình đưa đầu vào vào hệ thống. Một tiến trình vốn đã có quyền ghi lại cấu hình của người dùng là mô hình khác, có ý nghĩa bảo mật khác. Sau khi đặt tệp, thao tác kích hoạt được ghi nhận là mở **View → Function List**, từ đó khởi tạo bộ quản lý các bộ phân tích.

## Giới hạn dưới mới chỉ là một nửa phép kiểm tra

Bản chụp mã nguồn được cung cấp chứa logic sau trong `FunctionParsersManager::getOverrideMapFromXmlTree()`:

```cpp
const int langID = NppXml::intAttribute(childNode, "langID", -1);
if (langID >= 0)
{
    _parsers[langID] = std::make_unique<ParserInfo>(string2wstring(id));
}
```

Phép kiểm tra loại bỏ giá trị âm. Nó không xác lập rằng một giá trị không âm nằm trong mảng đích. Phiên bản liên quan có trong [mã nguồn bộ phân tích tại v8.9.8](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.8/PowerEditor/src/WinControls/FunctionList/functionParser.cpp).

Thành viên này được khai báo như sau:

```cpp
std::unique_ptr<ParserInfo> _parsers[L_EXTERNAL + nbMaxUserDefined];
```

Trong mã nguồn được xem, `L_EXTERNAL` bằng 96 và `nbMaxUserDefined` bằng 25. Vì vậy, bảng có **121 phần tử**, mang chỉ số từ **0 đến 120**. Chỉ số **121** đã nằm ngoài bảng. Một ghi chép nghiên cứu ban đầu ước tính khoảng 115 phần tử; báo cáo về sau sửa con số đó bằng cách đếm giá trị thực tế trong kiểu liệt kê và kiểm tra đúng ranh giới.

Nhánh bên cạnh dành cho tên ngôn ngữ do người dùng định nghĩa có kiểm tra chỉ số đang tăng so với kích thước mảng. Điều này làm sai sót đặc biệt rõ: hai đường đầu vào cùng điền dữ liệu vào một bảng, nhưng chỉ một đường áp dụng giới hạn trên.

Luồng dữ liệu khá ngắn:

```text
overrideMap.xml được đặt vào thư mục cấu hình
  → đọc association.langID dưới dạng số nguyên
  → kiểm tra giá trị không âm
  → gán con trỏ sở hữu tại _parsers[langID]
  → truy cập ngoài bảng khi langID ≥ 121
```

## Đối phương kiểm soát được gì

Giá trị XML kiểm soát chỉ số mảng, từ đó kiểm soát độ lệch so với bảng bộ phân tích. Nó **không** cung cấp một giá trị con trỏ tùy ý. `std::make_unique` tạo một `ParserInfo` mới; bộ cấp phát quyết định địa chỉ của đối tượng. XML cũng ảnh hưởng tới định danh bộ phân tích bên trong đối tượng đó.

Trên bản x64 đã thử, bảng chứa các con trỏ sở hữu kích thước tám byte. Phép gán qua một `unique_ptr` nằm ngoài biên là hành vi không xác định và có thể bao gồm truy cập hoặc giải phóng con trỏ cũ, bên cạnh việc lưu con trỏ mới. Chỉ riêng việc tiến trình kết thúc không chỉ ra lệnh máy nào đã gây lỗi.

Phân biệt này giúp mô tả chính xác phát hiện hữu ích: một chỉ số do đầu vào kiểm soát đi tới thao tác với con trỏ sở hữu bên ngoài bảng có kích thước cố định. Nó chưa xác lập khả năng ghi giá trị tùy ý tới địa chỉ tùy ý, hay một cách khai thác thực thi mã đã hoạt động.

## Thử nghiệm sát biên và các đối chứng

Các thử nghiệm ban đầu dùng bản portable mới, sửa một bản ghi liên kết, khởi chạy trình soạn thảo rồi mở Function List. Những phép thử sát biên về sau so sánh chỉ số hợp lệ cuối cùng với chỉ số không hợp lệ đầu tiên.

| Cấu hình | Kết quả được ghi nhận | Điều được xác lập |
|---|---|---|
| Tệp mặc định không sửa đổi | Bảng mở bình thường | Quá trình khởi tạo thông thường thành công |
| `langID = 120` | Tiến trình còn hoạt động trong 3/3 lần | Vị trí hợp lệ cuối cùng được chấp nhận |
| `langID = 121` | Crash trong 3/3 lần, `0xC000041D` | Lỗi bắt đầu đúng tại ranh giới mảng |
| `langID = 122` | Tiến trình còn hoạt động trong 3/3 lần | Chỉ số không hợp lệ không nhất thiết gây crash ngay |
| Một số giá trị lớn hơn, gồm 200 và 500 | Crash lặp lại | Lỗi không giới hạn ở một giá trị duy nhất |

`0xC000041D` báo một ngoại lệ nghiêm trọng trong hàm callback của ứng dụng. Những lần chạy khác tạo ra `0xC0000409`, một trạng thái fail-fast mà chỉ riêng tên của nó không chứng minh có tràn bộ đệm stack.

Mã nguồn xác lập vì sao giá trị ngoài biên không an toàn; các đối chứng gắn lỗi quan sát được với đường phân tích này. Ngược lại, kết quả “vẫn hoạt động” không cho biết chính xác đối tượng lân cận nào bị ảnh hưởng, cũng không chứng minh thao tác ghi đã rơi vô hại vào vùng đệm căn chỉnh. Ghi chép lịch sử mô tả những dải giá trị không gây crash là hỏng bộ nhớ âm thầm, nhưng không ghi lại bố cục các vùng cấp phát xung quanh cho từng lần chạy.

Advisory công khai có hướng dẫn tái hiện tối thiểu ban đầu. So sánh thực nghiệm quan trọng là **120 với 121**, kèm một cấu hình không thay đổi, thay vì tập hợp các đầu vào ngày càng lớn chỉ để gây crash.

## Ý nghĩa bảo mật và quá trình công bố

Nguyên tắc an toàn bộ nhớ bị vi phạm rất rõ: một trường cấu hình không được phép truy cập vùng lưu trữ bên ngoài bảng bộ phân tích. Tác động tới thuộc tính bảo mật được bảo vệ vẫn phụ thuộc vào cách cấu hình đi vào hệ thống.

Theo mô hình đối phương cung cấp cấu hình độc hại, nạn nhân cài cấu hình được cung cấp rồi mở bảng. Theo mô hình chỉ mã đã được tin cậy mới được phép sửa tệp này, cùng một sai sót có thể được xử lý như vấn đề về độ bền vững hoặc gia cố phần mềm. Advisory đã công bố giữ rõ sự phân biệt đó.

| Ngày | Sự kiện được ghi nhận |
|---|---|
| 29 tháng 8 năm 2026 | Thử nghiệm trên bản portable ghi nhận lỗi lặp lại và các đối chứng với tệp mặc định hoạt động bình thường |
| 1 tháng 9 năm 2026 | Báo cáo chỉnh sửa ghi nhận ranh giới chính xác của bảng 121 phần tử |
| 24 tháng 9 năm 2026 | Người bảo trì công bố GHSA-9rr8-6vjg-gj52 |

Tại thời điểm kiểm tra ngày 10 tháng 10 năm 2026, advisory liệt kê phiên bản bị ảnh hưởng là **8.9.8**, **chưa có CVE được biết đến**, và ghi **None** trong trường phiên bản đã vá. Siêu dữ liệu đó không xác lập hành vi của mọi bản build về sau. Điểm 5.5 là đánh giá đã công bố, không phải điểm số mới do bài viết này đưa ra. [Trạng thái và tác động đã công bố](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-9rr8-6vjg-gj52).

## Bài học triển khai

Bộ phân tích an toàn phải kiểm tra theo kích thước thực tế của vùng chứa trước khi dùng chỉ số. Nó cũng phải xác định giá trị có phải định danh ngôn ngữ hợp lệ hay không: nằm vừa trong vùng lưu trữ và có ý nghĩa với ứng dụng là hai phép kiểm tra riêng. Khi có thể, lấy giới hạn từ kích thước vùng chứa giúp tránh lặp lại một hằng số phụ thuộc vào kiểu liệt kê.

Kiểm tra nhánh nạp XML này bảo vệ đường đầu vào tương ứng. Những nơi khác sử dụng bảng bộ phân tích vẫn cần bảo đảm riêng về phạm vi chỉ số; giới hạn đã được kiểm tra trong một bộ phân tích không tự động bảo vệ đường xử lý khác.

Bài học rộng hơn là bộ phân tích cấu hình cần tuân thủ giới hạn bộ nhớ nghiêm ngặt như bộ phân tích tài liệu. Một trường được mô tả là định danh trở thành vấn đề an toàn bộ nhớ ngay khi mã dùng trực tiếp nó làm chỉ số mảng.
