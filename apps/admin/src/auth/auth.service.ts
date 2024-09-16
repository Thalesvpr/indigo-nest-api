import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthRepository } from './auth.repository';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
    private readonly saltRounds = 10;

    constructor(
        private readonly authRepository: AuthRepository,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) { }

    async validateAdmin(email: string, password: string): Promise<any> {
        const admin = await this.authRepository.findByEmail(email);
        if (!admin) {
            throw new UnauthorizedException('Admin not found');
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        const { password: _, ...result } = admin;
        return result;
    }

    async login(admin: any) {
        const payload = { email: admin.email, sub: admin.id, role: admin.role };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }

    async registerAdmin(email: string, name: string, password: string) {
        if (!this.configService.get<boolean>('ENABLE_ADMIN_MODULE')) {
            throw new ForbiddenException('Admin module is not enabled');
        }


        const existingAdmin = await this.authRepository.findByEmail(email);
        if (existingAdmin) {
            throw new ForbiddenException('Admin with this email already exists');
        }

        const hashedPassword = await bcrypt.hash(password, this.saltRounds);

        const newAdmin = await this.authRepository.create({
            name,
            email,
            password: hashedPassword,
            role: 'admin', // assuming role is 'admin' for all admins
        });

        const { password: _, ...result } = newAdmin;
        return result;
    }
}
