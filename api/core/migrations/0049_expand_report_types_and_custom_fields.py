# Generated for ShieldCall VN — expand Report TargetType/ScamType + custom fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0048_apikey'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='scammer_social',
            field=models.CharField(blank=True, default='', help_text='Kênh MXH của kẻ lừa đảo (link Telegram, nhóm Zalo, username FB, Fanpage)', max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='report',
            name='custom_fields',
            field=models.JSONField(blank=True, default=dict, help_text='Thông tin tuỳ biến có cấu trúc: thiệt hại, ví crypto, hash file, đơn vị giả mạo...'),
        ),
        migrations.AlterField(
            model_name='report',
            name='scam_type',
            field=models.CharField(choices=[('police_impersonation', 'Giả danh công an'), ('bank_impersonation', 'Giả mạo ngân hàng'), ('gov_impersonation', 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID'), ('recruitment_scam', 'Lừa tuyển dụng / Việc nhẹ lương cao'), ('investment_scam', 'Lừa đầu tư tài chính / Sàn ảo'), ('delivery_scam', 'Giả mạo giao hàng / Bưu cục'), ('loan_scam', 'Lừa vay tiền / Tín dụng đen'), ('otp_steal', 'Chiêu trò OTP/2FA'), ('phishing', 'Phishing link / Trang web giả mạo'), ('romance_scam', 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)'), ('deepfake', 'Deepfake âm thanh / Video AI mạo danh'), ('malware_app', 'Mã độc / Ứng dụng APK đánh cắp tài khoản'), ('crypto_scam', 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop'), ('social_engineering', 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage'), ('prize_scam', 'Trúng thưởng / Quà tri ân / Đơn hàng ảo'), ('emergency_scam', 'Báo nạn cấp cứu / Tống tiền người thân'), ('other', 'Khác')], max_length=30),
        ),
        migrations.AlterField(
            model_name='report',
            name='target_type',
            field=models.CharField(choices=[('phone', 'Số điện thoại'), ('domain', 'Website/URL'), ('account', 'Tài khoản ngân hàng'), ('message', 'Tin nhắn'), ('qr', 'QR Code'), ('email', 'Email'), ('file', 'Tệp tin / Ứng dụng APK độc hại'), ('audio', 'Cuộc gọi / Âm thanh Deepfake'), ('social', 'Mạng xã hội (Telegram/Zalo/FB)'), ('crypto', 'Địa chỉ ví Crypto / Web3')], max_length=20),
        ),
        migrations.AlterField(
            model_name='domain',
            name='scam_type',
            field=models.CharField(choices=[('police_impersonation', 'Giả danh công an'), ('bank_impersonation', 'Giả mạo ngân hàng'), ('gov_impersonation', 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID'), ('recruitment_scam', 'Lừa tuyển dụng / Việc nhẹ lương cao'), ('investment_scam', 'Lừa đầu tư tài chính / Sàn ảo'), ('delivery_scam', 'Giả mạo giao hàng / Bưu cục'), ('loan_scam', 'Lừa vay tiền / Tín dụng đen'), ('otp_steal', 'Chiêu trò OTP/2FA'), ('phishing', 'Phishing link / Trang web giả mạo'), ('romance_scam', 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)'), ('deepfake', 'Deepfake âm thanh / Video AI mạo danh'), ('malware_app', 'Mã độc / Ứng dụng APK đánh cắp tài khoản'), ('crypto_scam', 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop'), ('social_engineering', 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage'), ('prize_scam', 'Trúng thưởng / Quà tri ân / Đơn hàng ảo'), ('emergency_scam', 'Báo nạn cấp cứu / Tống tiền người thân'), ('other', 'Khác')], default='phishing', max_length=30),
        ),
        migrations.AlterField(
            model_name='bankaccount',
            name='scam_type',
            field=models.CharField(choices=[('police_impersonation', 'Giả danh công an'), ('bank_impersonation', 'Giả mạo ngân hàng'), ('gov_impersonation', 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID'), ('recruitment_scam', 'Lừa tuyển dụng / Việc nhẹ lương cao'), ('investment_scam', 'Lừa đầu tư tài chính / Sàn ảo'), ('delivery_scam', 'Giả mạo giao hàng / Bưu cục'), ('loan_scam', 'Lừa vay tiền / Tín dụng đen'), ('otp_steal', 'Chiêu trò OTP/2FA'), ('phishing', 'Phishing link / Trang web giả mạo'), ('romance_scam', 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)'), ('deepfake', 'Deepfake âm thanh / Video AI mạo danh'), ('malware_app', 'Mã độc / Ứng dụng APK đánh cắp tài khoản'), ('crypto_scam', 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop'), ('social_engineering', 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage'), ('prize_scam', 'Trúng thưởng / Quà tri ân / Đơn hàng ảo'), ('emergency_scam', 'Báo nạn cấp cứu / Tống tiền người thân'), ('other', 'Khác')], default='other', max_length=30),
        ),
        migrations.AlterField(
            model_name='trenddaily',
            name='scam_type',
            field=models.CharField(choices=[('police_impersonation', 'Giả danh công an'), ('bank_impersonation', 'Giả mạo ngân hàng'), ('gov_impersonation', 'Giả mạo cơ quan Thuế / Dịch vụ công / VNeID'), ('recruitment_scam', 'Lừa tuyển dụng / Việc nhẹ lương cao'), ('investment_scam', 'Lừa đầu tư tài chính / Sàn ảo'), ('delivery_scam', 'Giả mạo giao hàng / Bưu cục'), ('loan_scam', 'Lừa vay tiền / Tín dụng đen'), ('otp_steal', 'Chiêu trò OTP/2FA'), ('phishing', 'Phishing link / Trang web giả mạo'), ('romance_scam', 'Lừa tình cảm / Bẫy lợn béo (Pig Butchering)'), ('deepfake', 'Deepfake âm thanh / Video AI mạo danh'), ('malware_app', 'Mã độc / Ứng dụng APK đánh cắp tài khoản'), ('crypto_scam', 'Lừa đảo Tiền điện tử / Ví Crypto / Airdrop'), ('social_engineering', 'Lừa đảo hội nhóm Telegram / Zalo / Fanpage'), ('prize_scam', 'Trúng thưởng / Quà tri ân / Đơn hàng ảo'), ('emergency_scam', 'Báo nạn cấp cứu / Tống tiền người thân'), ('other', 'Khác')], max_length=30),
        ),
        migrations.AlterField(
            model_name='useralert',
            name='target_type',
            field=models.CharField(choices=[('phone', 'Số điện thoại'), ('domain', 'Website/URL'), ('account', 'Tài khoản ngân hàng'), ('message', 'Tin nhắn'), ('qr', 'QR Code'), ('email', 'Email'), ('file', 'Tệp tin / Ứng dụng APK độc hại'), ('audio', 'Cuộc gọi / Âm thanh Deepfake'), ('social', 'Mạng xã hội (Telegram/Zalo/FB)'), ('crypto', 'Địa chỉ ví Crypto / Web3')], max_length=20),
        ),
    ]
