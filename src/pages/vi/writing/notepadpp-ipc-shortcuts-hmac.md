---
layout: ../../../layouts/ArticleLayout.astro
lang: vi
title: "Độc lập phát hiện lại điểm yếu phê duyệt bằng HMAC trong Notepad++"
description: "Cách chúng tôi độc lập tìm ra điểm yếu về khóa HMAC có thể đọc được, biết rằng Nguyen Van Hiep đã báo cáo trước, và phân tích vai trò của nó trong chuỗi nâng quyền đã công bố."
published: "2026-10-10"
category: "Nghiên cứu bảo mật"
tags:
  - vulnerability-research
  - notepadpp
  - windows-security
  - trust-boundaries
draft: false
---

Trong quá trình nghiên cứu Notepad++, chúng tôi độc lập phát hiện rằng mã cục bộ thông thường có thể tính lại HMAC dùng để xác thực `shortcuts.xml`. Khóa là một định danh máy có thể đọc được, nên giá trị toàn vẹn khớp nhau không xác lập rằng người dùng đã phê duyệt tệp lệnh.

Sau đó, chúng tôi biết rằng **Nguyen Van Hiep thuộc Lo Security Labs đã gửi báo cáo về vấn đề này trước**. Notepad++ đã công bố báo cáo của Hiep dưới mã **GHSA-grw6-cw7j-3qfg** vào ngày 24 tháng 8 năm 2026. Công việc của chúng tôi là một lần phát hiện lại độc lập; ghi nhận người báo cáo đầu tiên thuộc về Hiep. [Advisory đã công bố trước đó](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-grw6-cw7j-3qfg).

Báo cáo trước đó kết nối khóa HMAC có thể đọc được với đường kích hoạt `WM_COMMAND` từ bên ngoài trong **8.9.7**, tạo thành chuỗi nâng quyền. Các thử nghiệm được lưu lại của chúng tôi thực hiện trên **8.9.8**, nơi hành vi của đường kích hoạt thông điệp đã khác. Bài viết giải thích cách chúng tôi đi đến cùng phát hiện về quản lý khóa và vai trò của nó trong chuỗi đã công bố, đồng thời phân biệt bằng chứng của hai phiên bản.

## Cách chúng tôi đi đến cùng phát hiện

Chúng tôi lần theo mã xác thực lệnh tới hàm hỗ trợ HMAC, nơi đọc `MachineGuid` từ Windows registry. Sau đó, chúng tôi kiểm tra liệu một tiến trình cục bộ thông thường có lấy được cùng giá trị và tái tạo phép tính của ứng dụng hay không. Trong thử nghiệm ngày 29 tháng 8, HMAC do công cụ của chúng tôi tính trùng với giá trị Notepad++ tạo ra trên cùng các byte của tệp lệnh.

Phép đối chiếu đó trả lời một câu hỏi cụ thể: khóa và phép tính của ứng dụng có thể được tái tạo bên ngoài quy trình phê duyệt. Lần đối chiếu đã dùng thao tác xác thực của ứng dụng, nên chỉ riêng việc digest trùng nhau chưa chứng minh một trạng thái phê duyệt mới bị giả mạo hay toàn bộ chuỗi nâng quyền hoạt động.

Lần tìm kiếm báo cáo trùng lặp ban đầu của chúng tôi bỏ sót advisory của Hiep. Bản đính chính ngày 31 tháng 8 xác định phần trùng lặp và rút tuyên bố rằng nguyên nhân gốc về khóa có thể đọc được là mới. Phát hiện độc lập mô tả cách chúng tôi tìm ra vấn đề; điều đó không thay đổi người đã báo cáo trước.

## Hai quyết định cần được bảo vệ riêng

Menu Run hỗ trợ các lệnh được lưu sẵn. Nội dung thực thi nằm trong `shortcuts.xml`; giá trị toàn vẹn dùng để đối chiếu nằm trong `config.xml`. Trước khi thực thi lệnh đã lưu, ứng dụng so sánh HMAC vừa tính với HMAC đã lưu. Nếu không khớp, ứng dụng dừng thực thi và cảnh báo. Báo cáo công khai có trích đoạn liên quan và tham chiếu [mã xử lý lệnh của 8.9.7](https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.7/PowerEditor/src/NppCommands.cpp).

Ở đây có hai câu hỏi bảo mật riêng:

- Đây có đúng là nội dung lệnh mà người dùng đáng tin cậy đã phê duyệt không?
- Yêu cầu thực thi có đến từ ngữ cảnh được phép hay không?

Chỉ trả lời một câu là chưa đủ. Nội dung đã được phê duyệt không nên trở thành thao tác đặc quyền tự chạy chỉ vì tiến trình khác có thể chọn mã định danh lệnh. Ngược lại, lời gọi hợp lệ không nên khiến cấu hình không đáng tin trông như đã được phê duyệt từ trước.

Đó là lý do trường hợp này được trình bày trong một chuỗi. Bước cấu hình chuẩn bị lệnh được chấp nhận; bước thông điệp kích hoạt lệnh ấy.

## Vì sao HMAC không xác lập được sự phê duyệt

Qua xem xét mã nguồn, chúng tôi xác định `MachineGuid`, đọc từ `HKLM\SOFTWARE\Microsoft\Cryptography`, là khóa HMAC-SHA256. Cùng người dùng cũng có thể ghi tệp lệnh và giá trị đối chiếu đã lưu. Điều này trùng với nguyên nhân gốc đã được mô tả trong báo cáo của Hiep: mã cục bộ có thể tạo lại giá trị toàn vẹn cho nội dung đã thay đổi. [Phần HMAC trong advisory trước đó](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-grw6-cw7j-3qfg).

Quan hệ khái niệm là:

```text
tệp lệnh + khóa xác thực → giá trị toàn vẹn
giá trị đã lưu == giá trị vừa tính → bước kiểm tra chấp nhận lệnh
```

HMAC xác thực dữ liệu trước các đối tượng không có khóa. Một định danh máy có thể ổn định và riêng cho máy mà vẫn không phải bí mật. Đặt giá trị trong registry của máy không có nghĩa tiến trình thông thường thiếu quyền đọc.

Nếu cùng một bên có thể đổi dữ liệu, lấy khóa và thay kết quả đối chiếu, hai giá trị trùng nhau chỉ xác lập tính nhất quán nội bộ. Chúng không xác lập ai đã phê duyệt nội dung. Không cần có điểm yếu trong SHA-256.

Quyền truy cập cấu hình của chính mình cũng không phải quyền hành động thông qua tiến trình đã nâng quyền. Hai tiến trình thuộc cùng người dùng Windows vẫn có thể nằm ở hai phía của một ranh giới bảo mật.

## Biến yêu cầu thành thực thi

Ứng dụng Windows thường nhận thông báo `WM_COMMAND` cho thao tác menu. Bộ xử lý ánh xạ mã định danh thành thao tác; mã ấy không chứng minh một người vừa chọn mục menu. Trong đường xử lý được báo cáo, vượt qua phép so sánh HMAC sẽ dẫn tới hàm thực thi lệnh đã lưu.

Quy tắc truyền thông điệp có ý nghĩa trước khi yêu cầu đến được bộ xử lý. Microsoft mô tả `SendMessageW` chịu sự kiểm soát của User Interface Privilege Isolation, viết tắt là UIPI, và một lần gửi bị UIPI chặn tạo lỗi từ chối truy cập số 5. Không thể suy ra an toàn hành vi tiếp nhận của ứng dụng chỉ từ giá trị số của thông điệp. [Tài liệu SendMessageW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagew).

Windows còn cung cấp bộ lọc theo từng cửa sổ và toàn tiến trình; một số thông điệp được xử lý đặc biệt. Vì thế, khái quát rằng “mọi thông điệp dưới `WM_USER` đều vượt mọi ranh giới toàn vẹn” là không chắc chắn. Phải xét cùng lúc tiến trình nguồn, cửa sổ đích, cấu hình bộ lọc và đường xử lý lệnh. [Tài liệu ChangeWindowMessageFilterEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-changewindowmessagefilterex).

Advisory trước đó báo cáo chuỗi từ Medium lên High. Thử nghiệm truyền thông điệp được hiển thị trong đó sử dụng hai tiến trình Low và Medium. Những quan sát ấy thuộc báo cáo trước; việc chúng tôi phát hiện lại điểm yếu về khóa không đồng nghĩa với việc đã độc lập tái hiện toàn bộ chuỗi trên 8.9.7 hay mọi sự chuyển tiếp mức toàn vẹn trong Windows.

## Điều kiện giúp hiểu đúng chuỗi

Ở mức khái quát, tình huống đã công bố nối các trạng thái sau:

```text
kẻ tấn công cục bộ cùng tài khoản
    → cấu hình lệnh được chuẩn bị cùng trạng thái toàn vẹn tương ứng
    → trình soạn thảo có quyền cao nạp trạng thái đó
    → yêu cầu bên ngoài đến được bộ xử lý lệnh
    → thao tác chạy với quyền cao của trình soạn thảo
```

Đây là tình huống cục bộ, không phải khai thác tài liệu gửi từ xa. Nó phụ thuộc vào việc trình soạn thảo có quyền cao sử dụng cấu hình mà tiến trình quyền thấp hơn có thể tác động. Chỉ sửa một tệp mà tiến trình đang chạy không bao giờ nạp lại chưa chứng minh lệnh đã chuẩn bị xuất hiện trong menu đang nằm trong bộ nhớ.

Cụm “zero-click” của advisory nói về bước kích hoạt sau khi tiến trình đã nâng quyền sẵn sàng. Nó không có nghĩa kẻ tấn công tự tạo quyền quản trị khi chưa có đích nâng quyền, hoặc vượt qua quyết định nâng quyền ban đầu của người dùng. Metadata CVSS ghi rõ cần tương tác người dùng.

## Trạng thái công khai và phạm vi bài viết

Dự án gắn mức **High, CVSS 3.1 8.2**, với vector `AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H`. Advisory liệt kê **8.9.7** là phiên bản bị ảnh hưởng, trường phiên bản đã vá là **None**, và chưa có CVE được biết đến. Đây là các trường thông tin đã công bố, không phải đánh giá mức độ nghiêm trọng mới. [Trạng thái advisory](https://github.com/notepad-plus-plus/notepad-plus-plus/security/advisories/GHSA-grw6-cw7j-3qfg).

Phép kiểm tra cục bộ của chúng tôi trên 8.9.8 ghi nhận yêu cầu `WM_COMMAND` từ Medium tới High bị từ chối với `ERROR_ACCESS_DENIED`. Kết quả âm có phạm vi hẹp đó không chứng minh toàn bộ chuỗi vẫn hoạt động trong 8.9.8. Nó cũng không cung cấp thông tin phiên bản sửa lỗi được nhà phát triển xác nhận khi advisory không nêu điều đó.

Bài học rộng hơn là phải bảo vệ cả thẩm quyền đối với cấu hình thực thi lẫn thẩm quyền gọi nó. Phép so sánh digest và thông điệp GUI mỗi thứ có một nhiệm vụ cụ thể. Sự kết hợp chỉ tạo thành ranh giới phân quyền khi khóa, phê duyệt đã lưu, nội dung được nạp và yêu cầu thực thi đều được bảo vệ phù hợp.
