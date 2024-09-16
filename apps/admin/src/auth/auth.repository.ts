import { Injectable } from '@nestjs/common';
import { Admin } from '@prisma/client';
import { PrismaService } from 'apps/admin/src/prisma/prisma.service';

@Injectable()
export class AuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: string): Promise<Admin | null> {
    return this.prisma.admin.findUnique({ where: { email } });
  }

  async create(data: { name: string; email: string; password: string; role: string }): Promise<Admin> {
    return this.prisma.admin.create({ data });
  }
}
