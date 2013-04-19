/****************************************************************************
**
** Copyright (C) 2012 Digia Plc and/or its subsidiary(-ies).
** Contact: http://www.qt-project.org/legal
**
** This file is part of the V4VM module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and Digia.  For licensing terms and
** conditions see http://qt.digia.com/licensing.  For further information
** use the contact form at http://qt.digia.com/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU Lesser General Public License version 2.1 requirements
** will be met: http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Digia gives you certain additional
** rights.  These rights are described in the Digia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
**
** $QT_END_LICENSE$
**
****************************************************************************/
#include "qv4lookup_p.h"
#include "qv4functionobject_p.h"

QT_BEGIN_NAMESPACE

using namespace QV4;

Property *Lookup::lookup(Object *obj, PropertyAttributes *attrs)
{
    int i = 0;
    while (i < level && obj && obj->internalClass == classList[i]) {
        obj = obj->prototype;
        ++i;
    }

    if (index != UINT_MAX && obj->internalClass == classList[i]) {
        *attrs = obj->internalClass->propertyData.at(index);
        return obj->memberData + index;
    }

    while (i < Size && obj) {
        classList[i] = obj->internalClass;

        index = obj->internalClass->find(name);
        if (index != UINT_MAX) {
            level = i;
            *attrs = obj->internalClass->propertyData.at(index);
            return obj->memberData + index;
        }

        obj = obj->prototype;
        ++i;
    }
    level = i;

    while (obj) {
        index = obj->internalClass->find(name);
        if (index != UINT_MAX) {
            *attrs = obj->internalClass->propertyData.at(index);
            return obj->memberData + index;
        }

        obj = obj->prototype;
    }
    return 0;
}


void Lookup::getterGeneric(QV4::Lookup *l, ExecutionContext *ctx, QV4::Value *result, const QV4::Value &object)
{
    if (Object *o = object.asObject()) {
        PropertyAttributes attrs;
        Property *p = l->lookup(o, &attrs);
        if (p) {
            if (attrs.isData()) {
                if (l->level == 0)
                    l->getter = getter0;
                else if (l->level == 1)
                    l->getter = getter1;
                else if (l->level == 2)
                    l->getter = getter2;
                if (result)
                    *result = p->value;
                return;
            } else {
                if (l->level == 0)
                    l->getter = getterAccessor0;
                else if (l->level == 1)
                    l->getter = getterAccessor1;
                else if (l->level == 2)
                    l->getter = getterAccessor2;
                if (result)
                    *result = p->value;
                Value res = o->getValue(ctx, p, attrs);
                if (result)
                    *result = res;
                return;
            }
        } else if (result) {
            *result = Value::undefinedValue();
        }
    } else {
        Value res;
        if (Managed *m = object.asManaged()) {
            res = m->get(ctx, l->name);
        } else {
            o = __qmljs_convert_to_object(ctx, object);
            res = o->get(ctx, l->name);
        }
        if (result)
            *result = res;
    }
}

void Lookup::getter0(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass) {
            if (result)
                *result = o->memberData[l->index].value;
            return;
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}

void Lookup::getter1(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass &&
            l->classList[1] == o->prototype->internalClass) {
            if (result)
                *result = o->prototype->memberData[l->index].value;
            return;
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}

void Lookup::getter2(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass) {
            o = o->prototype;
            if (l->classList[1] == o->internalClass) {
                o = o->prototype;
                if (l->classList[2] == o->internalClass) {
                    if (result)
                        *result = o->memberData[l->index].value;
                    return;
                }
            }
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}

void Lookup::getterAccessor0(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass) {
            Value res;
            FunctionObject *getter = o->memberData[l->index].getter();
            if (!getter)
                res = Value::undefinedValue();
            else
                res = getter->call(ctx, object, 0, 0);
            if (result)
                *result = res;
            return;
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}

void Lookup::getterAccessor1(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass &&
            l->classList[1] == o->prototype->internalClass) {
            Value res;
            FunctionObject *getter = o->prototype->memberData[l->index].getter();
            if (!getter)
                res = Value::undefinedValue();
            else
                res = getter->call(ctx, object, 0, 0);
            if (result)
                *result = res;
            return;
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}

void Lookup::getterAccessor2(Lookup *l, ExecutionContext *ctx, Value *result, const Value &object)
{
    if (Object *o = object.asObject()) {
        if (l->classList[0] == o->internalClass) {
            o = o->prototype;
            if (l->classList[1] == o->internalClass) {
                o = o->prototype;
                if (l->classList[2] == o->internalClass) {
                    Value res;
                    FunctionObject *getter = o->memberData[l->index].getter();
                    if (!getter)
                        res = Value::undefinedValue();
                    else
                        res = getter->call(ctx, object, 0, 0);
                    if (result)
                        *result = res;
                    return;
                }
            }
        }
    }
    l->getter = getterGeneric;
    getterGeneric(l, ctx, result, object);
}


void Lookup::globalGetterGeneric(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    PropertyAttributes attrs;
    Property *p = l->lookup(o, &attrs);
    if (p) {
        if (attrs.isData()) {
            if (l->level == 0)
                l->globalGetter = globalGetter0;
            else if (l->level == 1)
                l->globalGetter = globalGetter1;
            else if (l->level == 2)
                l->globalGetter = globalGetter2;
            *result = p->value;
            return;
        } else {
            if (l->level == 0)
                l->globalGetter = globalGetterAccessor0;
            else if (l->level == 1)
                l->globalGetter = globalGetterAccessor1;
            else if (l->level == 2)
                l->globalGetter = globalGetterAccessor2;
            Value res = o->getValue(ctx, p, attrs);
            if (result)
                *result = res;
            return;
        }
    }
    ctx->throwReferenceError(Value::fromString(l->name));
}

void Lookup::globalGetter0(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass) {
        *result = o->memberData[l->index].value;
        return;
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::globalGetter1(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass &&
        l->classList[1] == o->prototype->internalClass) {
        *result = o->prototype->memberData[l->index].value;
        return;
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::globalGetter2(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass) {
        o = o->prototype;
        if (l->classList[1] == o->internalClass) {
            o = o->prototype;
            if (l->classList[2] == o->internalClass) {
                *result = o->prototype->memberData[l->index].value;
                return;
            }
        }
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::globalGetterAccessor0(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass) {
        FunctionObject *getter = o->memberData[l->index].getter();
        if (!getter)
            *result = Value::undefinedValue();
        else
            *result = getter->call(ctx, Value::undefinedValue(), 0, 0);
        return;
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::globalGetterAccessor1(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass &&
        l->classList[1] == o->prototype->internalClass) {
        FunctionObject *getter = o->prototype->memberData[l->index].getter();
        if (!getter)
            *result = Value::undefinedValue();
        else
            *result = getter->call(ctx, Value::undefinedValue(), 0, 0);
        return;
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::globalGetterAccessor2(Lookup *l, ExecutionContext *ctx, Value *result)
{
    Object *o = ctx->engine->globalObject;
    if (l->classList[0] == o->internalClass) {
        o = o->prototype;
        if (l->classList[1] == o->internalClass) {
            o = o->prototype;
            if (l->classList[2] == o->internalClass) {
                FunctionObject *getter = o->memberData[l->index].getter();
                if (!getter)
                    *result = Value::undefinedValue();
                else
                    *result = getter->call(ctx, Value::undefinedValue(), 0, 0);
                return;
            }
        }
    }
    l->globalGetter = globalGetterGeneric;
    globalGetterGeneric(l, ctx, result);
}

void Lookup::setterGeneric(Lookup *l, ExecutionContext *ctx, const Value &object, const Value &value)
{
    Object *o = object.toObject(ctx);

    if (o->internalClass == l->classList[0]) {
        o->memberData[l->index].value = value;
        return;
    }

    uint idx = o->internalClass->find(l->name);
    if (!o->isArrayObject() || idx != ArrayObject::LengthPropertyIndex) {
        if (idx != UINT_MAX && o->internalClass->propertyData[idx].isData() && o->internalClass->propertyData[idx].isWritable()) {
            l->classList[0] = o->internalClass;
            l->index = idx;
            o->memberData[idx].value = value;
            return;
        }

        if (idx != UINT_MAX) {
            o->putValue(ctx, o->memberData + idx, o->internalClass->propertyData[idx], value);
            return;
        }
    }

    o->put(ctx, l->name, value);
}

QT_END_NAMESPACE
