---
layout: ../../../layouts/ArticleLayout.astro
title: "Quyết định cho phép chạy lệnh nằm trong cơ sở dữ liệu KeePassXC: Tìm hiểu _EXEC_CMD"
description: "Cách quyết định đã ghi nhớ cho cmd:// đi cùng cơ sở dữ liệu KeePassXC, kết quả thử nghiệm trên Windows và lý do nhà phát triển xem đây là nội dung được tin cậy."
published: "2026-08-30"
category: "Nghiên cứu bảo mật"
lang: vi
tags:
  - vulnerability-research
  - application-security
  - keepassxc
  - trust-boundaries
draft: false
---

KeePassXC có thể khởi chạy chương trình từ URL của một mục bắt đầu bằng `cmd://`. Thông thường, khi kích hoạt URL này, ứng dụng hiển thị hộp thoại xác nhận **Execute command?**. Trong nghiên cứu tháng 8 năm 2026, tôi nhận thấy cơ sở dữ liệu có thể mang theo câu trả lời đã ghi nhớ: thuộc tính `_EXEC_CMD` của mục, khi được đặt thành `1`, khiến hộp thoại không xuất hiện lúc URL được kích hoạt.

Điểm đáng chú ý nằm ở nơi lưu câu trả lời đó. Nó đi cùng lệnh bên trong cơ sở dữ liệu `.kdbx` được mã hóa. Vì vậy, người mở một cơ sở dữ liệu được chia sẻ có thể kế thừa quyết định mà người tạo đã ghi lại. **Chỉ mở hoặc mở khóa cơ sở dữ liệu không làm lệnh chạy; người dùng phải kích hoạt URL đã được chuẩn bị.**

Nhóm phát triển đã đóng báo cáo với kết luận đây là hành vi đúng theo thiết kế. Họ giải thích rằng nội dung cơ sở dữ liệu được tin cậy và cờ này giúp tránh thao tác vô ý, chứ không nhằm ngăn tấn công. Bài viết giữ nguyên kết luận đó, đồng thời giải thích hành vi quan sát được và giả định tin cậy khác đã dẫn đến báo cáo. Bài viết không coi đây là lỗ hổng được nhà phát triển xác nhận và không khẳng định có CVE hay bản vá.

*Nghiên cứu được thực hiện ngày 27 tháng 8 năm 2026; bài viết được cập nhật ngày 10 tháng 10 năm 2026 từ hồ sơ thử nghiệm, mã nguồn và trao đổi với nhóm phát triển đã lưu lại. Không thực hiện thử nghiệm chạy chương trình mới cho lần cập nhật này.*

## Tính năng này ghi nhớ điều gì?

Một mục trong KeePassXC có các trường thông thường như tiêu đề, tên đăng nhập, mật khẩu và URL, cùng các thuộc tính có tên do người dùng bổ sung. Tùy chọn **Remember my choice** trong hộp thoại xác nhận lệnh ghi một thuộc tính như vậy:

```text
URL        = cmd://cmd.exe /c calc.exe
_EXEC_CMD  = 1
```

Đây là ví dụ mở Calculator không gây hại đã được dùng trong các thử nghiệm trước đây. Thuộc tính này không phải thiết lập chỉ lưu trên máy tính từng hiển thị hộp thoại. Nó là dữ liệu của mục trong cơ sở dữ liệu.

Lịch sử mã nguồn cho thấy tính năng có hai phần riêng biệt. [Hộp thoại xác nhận được thêm ngày 27 tháng 1 năm 2017](https://github.com/keepassxreboot/keepassxc/commit/7ea306a61a7769042012ec267db64ca3b1a2c3ac), và [khả năng ghi nhớ câu trả lời được thêm ngày 28 tháng 1](https://github.com/keepassxreboot/keepassxc/commit/01e9d39b63b500944c59adbe163e6d5a8bfa57b0). Trong lịch sử kho mã đã lưu, 2.1.1 là thẻ phiên bản phát hành sớm nhất chứa thay đổi lưu quyết định này. Điều đó xác định lịch sử tính năng, không có nghĩa mọi phiên bản từ đó trở đi đều đã được chạy thử.

Thử nghiệm thực tế sử dụng KeePassXC **2.7.12**, bản cài qua Scoop dùng Qt 5.15, trên **Windows 10 19045 x64**. Việc đọc mã nguồn dựa trên commit phát triển [`79c3c379acf53a5d402059148aaf4d2f5f1c2475`](https://github.com/keepassxreboot/keepassxc/commit/79c3c379acf53a5d402059148aaf4d2f5f1c2475), được nhật ký nghiên cứu ghi nhận là trùng với upstream vào ngày 27 tháng 8. Đây là phạm vi phiên bản tại thời điểm nghiên cứu; bài viết không khẳng định trạng thái của các bản phát hành sau đó.

## Đường đi từ nội dung cơ sở dữ liệu đến tiến trình

Bốn phần mã nguồn giải thích kết quả này.

**Thứ nhất, tên cờ là một thuộc tính thông thường của mục.** [`EntryAttributes.cpp`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/core/EntryAttributes.cpp#L37) định nghĩa `RememberCmdExecAttr` là `_EXEC_CMD`. Trong XML đã giải mã của cơ sở dữ liệu, thuộc tính này là một cặp khóa/giá trị `<String>`, giống các trường bổ sung khác:

```xml
<String>
  <Key>_EXEC_CMD</Key>
  <Value Protected="False">1</Value>
</String>
```

Dấu `Protected` liên quan đến cách bảo vệ trường trong cấu trúc KDBX; giá trị của nó không xác nhận ai đã cho phép chạy lệnh. Toàn bộ cơ sở dữ liệu vẫn được mã hóa. Đây không phải cách tấn công cơ chế mã hóa đó.

**Thứ hai, quá trình tải khôi phục trường này như dữ liệu.** [`KdbxXmlReader::parseEntryString()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/format/KdbxXmlReader.cpp#L834-L875) đọc từng khóa và giá trị, rồi gọi:

```cpp
entry->attributes()->set(key, value, protect);
```

Bộ đọc thực hiện các kiểm tra cấu trúc thông thường, trong đó có kiểm tra khóa trùng, nhưng không xem `_EXEC_CMD` là trạng thái riêng của người nhận. [Bộ ghi XML duyệt qua các khóa thuộc tính của mục](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/format/KdbxXmlWriter.cpp#L416-L450) khi lưu, nên giá trị này còn nguyên sau khi lưu và tải lại.

**Thứ ba, thao tác kích hoạt URL sử dụng giá trị đó như quyết định cho phép.** Nhánh liên quan trong [`DatabaseWidget::openUrlForEntry()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/gui/DatabaseWidget.cpp#L997-L1053) tương đương đoạn mã rút gọn sau:

```cpp
bool launch =
    (entry->attributes()->value(EntryAttributes::RememberCmdExecAttr) == "1");

if (!launch && cmdString.length() > 6) {
    // Hiển thị hộp thoại xác nhận; câu trả lời mặc định là No.
    // Câu trả lời được ghi nhớ sẽ được lưu lại vào thuộc tính của mục.
}

if (launch) {
    const QString cmd = cmdString.mid(6);
    QStringList cmdList = QProcess::splitCommand(cmd);
    if (!cmdList.isEmpty()) {
        const QString program = cmdList.takeFirst();
        QProcess::startDetached(program, cmdList);
    }
}
```

Giá trị `1` được tải từ tệp làm `launch` trở thành true trước nhánh hiển thị hộp thoại. Phần còn lại của URL được tách thành tên chương trình và các đối số, sau đó truyền vào `QProcess::startDetached`. Trong ví dụ Calculator, `cmd.exe` được ghi rõ trong URL; KeePassXC không tự coi mọi URL là mã lệnh shell.

**Thứ tư, chỉnh sửa và tải dữ liệu đi qua hai đường khác nhau.** [`Entry::setUrl()`](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/core/Entry.cpp#L781-L790) xóa thuộc tính ghi nhớ khi URL của mục thay đổi. Vì vậy, chỉnh URL theo cách thông thường sẽ xóa quyết định cũ. Khi tải cơ sở dữ liệu, URL và các thuộc tính được khôi phục qua bộ đọc chung, nên một URL cùng `_EXEC_CMD` tương ứng có thể xuất hiện đồng thời từ tệp.

```text
Cơ sở dữ liệu được chia sẻ
  URL = cmd://…       _EXEC_CMD = 1
           │                │
           └───────┬────────┘
                   ▼
       Tải các thuộc tính của mục
                   │
       Người dùng kích hoạt URL
                   │
                   ▼
       Câu trả lời đã nhớ là "yes"
                   │
       Bỏ qua nhánh xác nhận
                   │
                   ▼
  Chạy chương trình bằng tài khoản hiện tại
```

Cách triển khai không phân biệt giá trị được tạo từ hộp thoại trên máy tính này với giá trị giống hệt được cung cấp trong cơ sở dữ liệu. Để gọi đây là vi phạm ranh giới bảo mật, cần thêm một giả định: người tạo cơ sở dữ liệu không nên có quyền cung cấp quyết định cho phép chạy lệnh thay người nhận. Đây chính là điểm khác biệt giữa giả định của báo cáo và mô hình của nhóm phát triển.

## Các thử nghiệm đã ghi nhận điều gì?

Cơ sở dữ liệu thử nghiệm chứa các mục chạy lệnh và một mục đối chứng không có thuộc tính này trong bản sao dùng để kiểm tra. Việc đọc rồi ghi lại bằng bộ phân tích độc lập, cùng việc kiểm tra XML đã giải mã, xác nhận `_EXEC_CMD` là dữ liệu được lưu bình thường trong tệp.

| Trường hợp | Trạng thái của mục | Kết quả được ghi nhận |
|---|---|---|
| Lệnh có quyết định cho phép đã ghi nhớ | Lệnh vô hại ghi thông tin tài khoản ra tệp, `_EXEC_CMD = 1` | Ba lần chạy với tiến trình mới đều tạo tệp tạm dự kiến; không tìm thấy cửa sổ **Execute command?**. |
| Calculator có quyết định đã ghi nhớ | `cmd://cmd.exe /c calc.exe`, `_EXEC_CMD = 1` | Calculator khởi chạy mà không có hộp thoại xác nhận. |
| Mục Calculator đối chứng | Cùng URL Calculator, không có thuộc tính | Hộp thoại xuất hiện trong hai lần kích hoạt. Từ chối không làm Calculator khởi chạy. |

Với trường hợp chạy lệnh lặp lại, tệp đầu ra được xóa trước mỗi lần thử và được tạo lại sau khi kích hoạt URL. Kiểm tra tác động thực tế, thay vì chỉ dựa vào giá trị trả về của API khởi chạy, giúp phân biệt việc chương trình đã chạy với việc mới yêu cầu khởi chạy. Mục Calculator đối chứng tách được biến quan trọng: văn bản lệnh giống nhau, nhưng không có thuộc tính.

Bộ tự động hóa có kiểm soát chọn ô URL rồi nhấn Enter. Nó không mô phỏng nhấp đúp ổn định khi điều kiện DPI/phiên làm việc thay đổi. Mã nguồn cho thấy [đường xử lý kích hoạt ở cột URL](https://github.com/keepassxreboot/keepassxc/blob/79c3c379acf53a5d402059148aaf4d2f5f1c2475/src/gui/DatabaseWidget.cpp#L1581-L1593) đi đến `openUrlForEntry()`. Một phiên thao tác thủ công trước đó cũng cho kết quả phù hợp, nhưng không được tính là lần lặp có kiểm soát.

Kết luận không có hộp thoại dựa trên cả việc kiểm tra cửa sổ của tiến trình và nhánh xử lý trong mã nguồn. Nó không chứng minh rằng mọi cấu hình desktop, nền tảng hay phiên bản sau này đều hoạt động giống nhau.

## Điều kiện và giới hạn

Kịch bản đã chứng minh cần đủ các điều kiện sau:

1. Một bên khác có thể tạo cơ sở dữ liệu, hoặc giải mã, chỉnh sửa và lưu cơ sở dữ liệu mà họ đã có thông tin mở khóa.
2. Người nhận có được cơ sở dữ liệu đó và thông tin cần thiết để mở khóa.
3. Một mục chứa cả URL `cmd://` và `_EXEC_CMD = 1`.
4. Người nhận kích hoạt URL của mục.

Kịch bản gửi tệp không yêu cầu truy cập trước vào máy tính của người nhận. Ngược lại, chỉ có bản sao cơ sở dữ liệu đã mã hóa không đủ để chèn trường này. Phát hiện không vượt qua cơ chế xác thực hay bảo vệ toàn vẹn của KDBX, không khôi phục mật khẩu chính và không nâng quyền. Tiến trình được chạy với quyền sẵn có của tài khoản người nhận.

Một ví dụ cụ thể về khác biệt kỳ vọng tin cậy là bàn giao thông tin đăng nhập. Đồng nghiệp hoặc nhà thầu chia sẻ một kho mật khẩu; người nhận xem các mật khẩu trong đó là dữ liệu hữu ích và kích hoạt URL của một mục. Họ có thể không nhận ra cùng kho đó còn mang theo quyết định chạy lệnh đã ghi nhớ. URL vẫn có thể hiển thị tiền tố `cmd://`; nghiên cứu này không chứng minh cơ chế giả mạo hiển thị URL hay tự chạy khi mở cơ sở dữ liệu.

Mã nguồn cũng giải thích vì sao về nguyên tắc không cần chỉnh XML bằng công cụ riêng. Người tạo cơ sở dữ liệu có thể dùng quy trình **Remember my choice** thông thường rồi lưu cơ sở dữ liệu. Đây là suy luận từ đường lưu và tải dữ liệu, tách biệt với các thử nghiệm có kiểm soát vốn dùng cơ sở dữ liệu đã chuẩn bị sẵn.

Hồ sơ **không** xác nhận hành vi chạy thực tế trên Linux hoặc macOS, khả năng tự động chuyển dữ liệu qua KeeShare, hay tác động sau thực thi ngoài các minh họa vô hại. Hồ sơ còn có một quan sát độc lập về `file://`. Đường này sử dụng nhánh xử lý và cơ chế khởi chạy khác; nó không phải bước tiếp theo trong một chuỗi khai thác của phát hiện này.

## Phản hồi của nhóm phát triển và giả định gây tranh luận

Phần trao đổi trong báo cáo đã lưu ghi nhận diễn biến sau:

| Ngày | Sự kiện |
|---|---|
| 27 tháng 8 năm 2026 | Báo cáo về quyết định chạy lệnh được gửi riêng cho nhóm phát triển. |
| 27 tháng 8 năm 2026 | Một thành viên đóng báo cáo, giải thích rằng nội dung cơ sở dữ liệu được tin cậy và hành vi đúng theo thiết kế. |
| 28 tháng 8 năm 2026 | Phản hồi tiếp theo làm rõ cờ này giúp tránh thao tác vô ý, không nhằm ngăn tấn công. |
| 30 tháng 8 năm 2026 | Phiên bản đầu tiên của bài viết. |
| 10 tháng 10 năm 2026 | Cập nhật bám sát bằng chứng và bổ sung bản tiếng Việt. |

Giải thích ngắn gọn của nhóm phát triển, dịch sang tiếng Việt:

> “Cờ này tồn tại để tránh thao tác vô ý, không phải để ngăn tấn công. Nội dung cơ sở dữ liệu được coi là đáng tin cậy.”

Trích dẫn được dịch từ phần trao đổi riêng đã lưu của báo cáo. Nó được đưa vào để giải thích kết luận xử lý; bản xuất HTML riêng tư, thông tin cộng tác và dữ liệu phiên đăng nhập không được công bố ở đây. Hồ sơ lưu lại không cung cấp một thông báo bảo mật công khai của nhà phát triển để dẫn làm bằng chứng rằng phát hiện đã được chấp nhận.

Báo cáo ban đầu của tôi xem hộp thoại là ranh giới cho phép thực thi tại máy cục bộ: cho phép chạy lệnh trên một máy không nên đồng nghĩa với việc cho phép thay người nhận ở máy khác. Nhóm phát triển đặt nội dung cơ sở dữ liệu đã mở khóa bên trong ranh giới tin cậy. Theo mô hình đó, ghi nhớ quyết định trong cơ sở dữ liệu phù hợp với việc tin người tạo, và hộp thoại vẫn có ích để tránh lần kích hoạt đầu tiên do vô ý.

Bản thân cơ chế quan sát được không thể quyết định bất đồng về chính sách này. Một hộp thoại có thể giúp tránh thao tác nhầm mà không cam kết bảo vệ trước nội dung tệp độc hại. Tương tự, người chia sẻ kho mật khẩu vẫn cần biết giả định tin cậy của ứng dụng rộng đến đâu. Giá trị cho cộng đồng là làm rõ cả hai điều đó.

## Bài học thực tế

Hãy xem URL của các mục trong kho nhận từ bên ngoài là nội dung có thể kích hoạt hành động. Kiểm tra hành động thực tế sau khi xử lý URL trước khi kích hoạt. Xóa `_EXEC_CMD` khôi phục việc hỏi xác nhận cho `cmd://` trong mã đã xem, nhưng không tạo thành chính sách mở an toàn cho mọi URL: đường `file://` riêng biệt không đọc thuộc tính này.

Với ứng dụng muốn quyết định cho phép thuộc về từng người nhận, bài học thiết kế là giữ quyết định đó bên ngoài nội dung do người tạo kiểm soát. Quyết định cục bộ có thể gắn với danh tính cơ sở dữ liệu, danh tính mục và giá trị lệnh; khi chúng thay đổi thì cần xác nhận lại. Chỉ ghi nhớ trong một phiên làm việc cũng là một phương án. Cả hai đều có đánh đổi về chuyển dữ liệu giữa máy hoặc tính tiện dụng, và bài viết không nói rằng KeePassXC đã áp dụng chúng làm bản vá.

Điểm cần phân biệt là tin cơ sở dữ liệu cung cấp bí mật với tin nó cung cấp cả hành động thực thi và quyết định cho phép đã ghi nhớ. Phản hồi của KeePassXC đặt cả hai trong cùng một ranh giới. Các thử nghiệm cho thấy lựa chọn đó có ý nghĩa gì khi cơ sở dữ liệu được chuyển giữa người dùng hoặc máy tính.
